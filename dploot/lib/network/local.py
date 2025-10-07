import ntpath
import os
import logging

from pathlib import Path
from typing import Any, Optional

from dploot.lib.network import DPLootConnection

from impacket.smb import SharedFile
from impacket.winregistry import Registry
from impacket.smb import ATTR_DIRECTORY
from impacket.examples.secretsdump import LocalOperations
from impacket.smb import FILE_SHARE_READ
from impacket.smb3structs import (
    FILE_OPEN
)

class DPLootLocalConnection(DPLootConnection):
    systemroot = "C:\\Windows"
    hklm_software_path = r"Windows/System32/config/SOFTWARE"

    def __init__(self, target=None) -> None:
        super().__init__(target)
        self.local_ops = None
        self.local_session = True
        self.smb_session = DPLootDummySession()
        # the following are functions that should never be called on this class.
        self.enable_remoteops = None
        self.reconnect = None


    def connect(self) -> "Any | None":
        return self.smb_session

    def is_admin(self) -> bool:
        return True

    def enable_localops(self, systemHive, force=False) -> None:
        if self.local_ops is not None and self.bootkey is not None and not force:
            return
        try:
            self.local_ops = LocalOperations(systemHive)
            self.bootkey = self.local_ops.getBootKey()
        except Exception as e:
            logging.error(f"LocalOperations failed: {e}")

    # we 'emulate' remote file operations by converting local os.DirEntry() to impacket.SharedFile()
    def _sharedfile_fromdirentry(d: os.DirEntry):
        (filesize, atime, mtime, ctime) = d.stat(follow_symlinks=False)[6:]
        attribs = 0
        if d.is_dir(follow_symlinks=False):
            attribs |= ATTR_DIRECTORY
        return SharedFile(ctime, atime, mtime, filesize, None, attribs, d.name, d.name)

    SharedFile.fromDirEntry = _sharedfile_fromdirentry

    def remote_list_dir(self, share, path, wildcard=True) -> list[SharedFile]:
        path = self.get_real_path(path)
        if not wildcard:
            raise NotImplementedError("Not implemented for wildcard == False")
        try:
            result = list(map(SharedFile.fromDirEntry, os.scandir(path)))
        except FileNotFoundError:
            result = []
        return result

    def list_users(self, share):
        users_dir_path = "Users\\*"
        directories = self.listPath(
            shareName=share, path=ntpath.normpath(users_dir_path)
        )
        return [d.get_longname() for d in directories if d.get_longname() not in self.false_positive and d.is_directory() > 0]

    def listPath(self, shareName: str = "C$", path: Optional[str] = None, password: Optional[str] = None):
        if path[-2:] == r"\*":
            return self.remote_list_dir(shareName, path[:-2], wildcard=True)
        if path[-1] == "*":
            return self.remote_list_dir(shareName, path[:-1], wildcard=True)
        else:
            raise NotImplementedError("Not implemented for wildcard == False")

    def getFile(self, *args, **kwargs) -> "Any | None":
        raise NotImplementedError("getFile is not implemented in LOCAL mode")

    def get_real_path(self, path:str) -> str:
        """Match path against file system (case insensitive if py>=3.12).
            Only used when target is `LOCAL`.

        Args:
            path (str): pah representation (ie C:\\Windows\\...)

        Returns:
            str: real path on the filesystem
        """
        # clean path (remove c:\, /, and current root if already present)
        path=path.removeprefix(self.target.local_root)
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

    def readFile(
        self,
        shareName,
        path,
        mode=FILE_OPEN,
        offset=0,
        password=None,
        shareAccessMode=FILE_SHARE_READ,
        bypass_shared_violation=False,
        looted_files=None
    ) -> bytes:
        data = None
        try:
            with open(self.get_real_path(path), "rb") as f:
                data = f.read()
        except Exception as e:
            logging.debug(f"Exception occurred while trying to read {path}: {repr(e)}")

        return data

    def getUsersProfiles(self) -> dict[str, str] | None:
        """Returns the list of user profiles (from registry) in a dict

        Each subkey of HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProfileList is a user SID,
        and the ProfileImagePath value inside is the path to the user's profile
        :return: dict of user_sid: path_to_profile

        """
        if self._usersProfiles is not None:
            return self._usersProfiles

        result = {}
        # open hive
        reg_file_path = self.get_real_path(self.hklm_software_path)
        reg = Registry(reg_file_path, isRemote=False)

        # open key
        key_path = "Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
        parentKey = reg.findKey(key_path)
        if parentKey is None:
            logging.error(f"Key {key_path} not found in {reg_file_path}")
            return None

        for user_sid in reg.enumKey(parentKey):
            # get 'ProfileImagePath' value
            (_, path) = reg.getValue(
                ntpath.join(key_path, user_sid, "ProfileImagePath")
            )
            path = (
                path.decode("utf-16le")
                .rstrip("\0")
                .replace(r"%systemroot%", self.systemroot)
            )
            path = ntpath.normpath(path)
            path = self.get_real_path(path)
            # store in result dict
            result[user_sid] = path

        self._usersProfiles = result
        return self._usersProfiles


class DPLootDummySession:
    def login(*args, **kwargs) -> bool:
        return True
