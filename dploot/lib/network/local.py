from binascii import unhexlify
import ntpath
import os
import logging
import argparse

from pathlib import Path
from typing import Any, Dict, List, Optional

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target

from impacket.smb import SharedFile
from impacket.winregistry import get_registry_parser
from impacket.smb import ATTR_DIRECTORY
from impacket.examples.secretsdump import LocalOperations, LSASecrets


class DPLootLocalConnection(DPLootConnection):
    systemroot = "C:\\Windows"
    hklm_software_path = r"Windows/System32/config/SOFTWARE"

    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.local_session = True
        self._usersProfiles = None
        self._local_ops = None
        self._bootkey = None

    # we 'emulate' remote file operations by converting local os.DirEntry() to impacket.SharedFile()
    def __sharedfile_fromdirentry(d: os.DirEntry):
        (filesize, atime, mtime, ctime) = d.stat(follow_symlinks=False)[6:]
        attribs = 0
        if d.is_dir(follow_symlinks=False):
            attribs |= ATTR_DIRECTORY
        return SharedFile(ctime, atime, mtime, mtime, filesize, None, attribs, d.name, d.name)

    SharedFile.fromDirEntry = __sharedfile_fromdirentry

    def __get_real_path(self, path:str) -> str:
        """Match path against file system (case insensitive if py>=3.12).
            Only used when target is `LOCAL`.

        Args:
            path (str): pah representation (ie C:\\Windows\\...)

        Returns:
            str: real path on the filesystem

        """
        # clean path (remove c:\, /, and current root if already present)
        path=path.removeprefix(self.target.local_root)
        if r"%systemroot%" in path:
            path = path.replace(r"%systemroot%", self.systemroot)
        if path[:3].lower() == "c:\\":
            path = path[3:]
        path=path.replace("\\", os.sep).lstrip(os.sep)

        globok = False
        # The pattern to match does not contain jokers, so Path.glob() should return 0 or 1 match
        try:
            path=next(Path(self.target.local_root).glob(path, case_sensitive=False))
            globok=True
        except (StopIteration, TypeError):
            # StopIteration: path does not exist.
            # TypeError: unexpexted keyword (case_sensitive added in python 3.12)
            # Return a representation of path anyway
            path=os.path.join(self.target.local_root, path)

        #logging.debug(f"get_real_path: [{globok=}] returning {path}")
        return str(path)
    
    def __get_user_profile(self, sid:str) -> str | None:
        userlist_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        profile_path = self.reg_get_key_value("HKLM",f"{userlist_key}\\{sid}","ProfileImagePath")
        return profile_path

    def __open_corresponding_hive(self, hive:str, path:str):
        if hive.lower() == "hklm":
            if path[:9] == "SOFTWARE\\":
                return self.__get_real_path(r"Windows/System32/config/SOFTWARE"), path[8:]
            else:
                raise ValueError(f"__open_corresponding_hive not implemented for path {hive}\\{path}")
        elif hive.lower() == "hku":
            sid,tail = path.split("\\",1)
            profile_path = self.__get_user_profile(sid)
            return self.__get_real_path(os.path.join(profile_path,"NTUSER.DAT")), tail
        else:
            raise ValueError(f"__open_corresponding_hive not implemented for hive {hive}")
    
    def __get_registry_if_exists(self, reg_filepath):
        try:
            return get_registry_parser(reg_filepath, isRemote=False)
        except FileNotFoundError:
            logging.debug(f"Could not find {reg_filepath}")
            return None 

    @property
    def local_ops(self) -> LocalOperations:
        if self._local_ops is not None:
            return self._local_ops
        logging.getLogger("impacket").disabled = True
        try:
            self._local_ops = LocalOperations(
                    os.path.join(
                        self.target.local_root, r"Windows/System32/config/SYSTEM"
                    )
                )
        except Exception as e:
            logging.error(f"LocalOperations failed: {e}")

        return self._local_ops
    
    @property
    def bootkey(self):
        if self._bootkey is not None:
            return self._bootkey
        if os.path.exists(os.path.join(self.target.local_root, "Windows/System32/config/SYSTEM_bootkey")):
            self._bootkey = self.read_file("Windows/System32/config/SYSTEM_bootkey")
        else:
            self._bootkey = self.local_ops.getBootKey()
        return self._bootkey

    # Common protocol functions

    def print_connected_info(self) -> None:
        logging.info(f"Reading {os.path.abspath(self.target.local_root)}")

    def connect(self) -> bool:
        return True
    
    def list_dir(self, path, share:str="N/A", wildcard=True) -> list[SharedFile]:
        path = self.__get_real_path(path)
        if not wildcard:
            raise NotImplementedError("Not implemented for wildcard == False")
        try:
            result = list(map(SharedFile.fromDirEntry, os.scandir(path)))
        except FileNotFoundError:
            result = []
        return result

    def is_admin(self) -> bool:
        return True
    
    def read_file(
        self,
        path,
        share:str="N/A",
        looted_files=None,
    ) -> bytes:
        data = None
        try:
            with open(self.__get_real_path(path), "rb") as f:
                data = f.read()
        except Exception as e:
            logging.debug(f"Exception occurred while trying to read {path}: {e!r}")

        return data
    
    def reg_enum_key(self, hive:str, path:str) -> List[str]:
        keys = []
        hive_filepath, key_path = self.__open_corresponding_hive(hive, path)
        reg = self.__get_registry_if_exists(hive_filepath)
        if reg is None:
            return keys
        parentKey = reg.findKey(key_path)
        if parentKey is None:
            logging.error(f"Key {key_path} not found in {hive_filepath}")
            return keys
        keys = reg.enumKey(parentKey)
        reg.close()
        return keys
    
    def reg_enum_values(self, hive:str, keypath:str) -> List[str]:
        values = []
        hive_filepath, key_path = self.__open_corresponding_hive(hive, keypath)
        reg = self.__get_registry_if_exists(hive_filepath)
        if reg is None:
            return values
        values = reg.enumValues(key_path)
        reg.close()
        return values

    def reg_get_key_value(self, hive:str, keypath:str, value_name:str) -> Any:
        value = None
        hive_filepath, updated_key_path = self.__open_corresponding_hive(hive, keypath)
        reg = self.__get_registry_if_exists(hive_filepath)
        if reg is None:
            return value
        (_, value) = reg.getValue(
            ntpath.join(updated_key_path, value_name)
        )
        if type(value) == bytes: 
            value = value.decode("utf-16le")
        reg.close()
        return value.rstrip("\0")

    def get_dpapi_system_keys(self, looted_files=None) -> Dict[str,bytes]:
        dpapiSystem = {}
        logging.getLogger("impacket").disabled = True
        SECURITYFileName = os.path.join(
            self.target.local_root, r"Windows/System32/config/SECURITY"
        )
        
        def getDPAPI_SYSTEM(_, secret) -> None:
            if secret.startswith("dpapi_machinekey:"):
                machineKey, userKey = secret.split("\n")
                machineKey = machineKey.split(":")[1]
                userKey = userKey.split(":")[1]
                dpapiSystem["MachineKey"] = unhexlify(machineKey[2:])
                dpapiSystem["UserKey"] = unhexlify(userKey[2:])

        try:
            LSA = LSASecrets(
                SECURITYFileName,
                self.bootkey,
                self.local_ops,
                isRemote=False,
                perSecretCallback=getDPAPI_SYSTEM,
            )
            LSA.dumpSecrets()
            LSA.finish()
        except Exception as e:
            logging.error("LSA hashes extraction failed: %s" % str(e))

        return dpapiSystem

class LocalTarget(Target):
    def __init__(self) -> None:
        self.username: str = None
        self.password: str = None
        self.address: str = None
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.local_root: str = None

    @staticmethod
    def from_options(options) -> "Target":
        return LocalTarget.create(
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            hashes=options.hashes,
            lmhash=None,
            nthash=None,
            local_root=options.root,
        )

    @staticmethod
    def create(
        username: str = "",
        password: str = "",
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        local_root: Optional[str] = None,
    ) -> "Target":
        self = LocalTarget()
        self.protocol = "local"

        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        elif lmhash is None and nthash is None:
            lmhash = nthash = ""

        self.username = username
        self.password = password
        self.address = local_root
        self.lmhash = lmhash
        self.nthash = nthash
        self.local_root = local_root

        return self

    @staticmethod
    def add_network_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
        group = parser.add_argument_group("local authentication")
        group.add_argument(
            "-r",
            "--root",
            action="store",
            dest="root",
            metavar="path",
            default=".",
            help="Path of the Windows Root directory. This directory should contain Windows and Users subdirectories",
        )

        group.add_argument(
            "-u",
            "--username",
            metavar="username",
            dest="username",
            action="store",
            help="Username. Will be use to potentially decrypt masterkeys",
        )

        group.add_argument(
            "-p",
            "--password",
            metavar="password",
            dest="password",
            action="store",
            help="Password. Will be use to potentially decrypt masterkeys",
        )

        group.add_argument(
            "--hashes",
            action="store",
            metavar="LMHASH:NTHASH",
            help="NTLM hashes, format is LMHASH:NTHASH. Will be use to potentially decrypt masterkeys",
        )

    def create_connection_object(self):
        return DPLootLocalConnection(self)