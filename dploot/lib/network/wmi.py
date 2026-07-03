import logging
import struct
import time
import os
import argparse
from typing import Any, Dict, List, Optional

from impacket.smb import SharedFile, ATTR_DIRECTORY
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target


class DPLootWMIConnection(DPLootConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.dcom = None

        self._cimv2_namespace = None
        self._pwshellv3_namespace = None
        self._default_namespace = None
        self._managementtools_namespace = None

    def get_namespace(self, namespace_name:str):
        namespace = self.iWbemLevel1Login.NTLMLogin(namespace_name, NULL, NULL)
        self.iWbemLevel1Login.RemRelease()
        return namespace

    def execute_wmi_query(self, query, namespace=None):
        if namespace is None:
            namespace = self.cimv2_namespace
        logging.debug(f"Executing WQL Query: {query}")
        return namespace.ExecQuery(query)
    
    def __check_error(self, banner, resp) -> bool:
        call_status = resp.GetCallStatus(0) & 0xffffffff
        if call_status != 0:
            try:
                error_name = wmi.WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = "Unknown"
            logging.error("%s - ERROR: %s (0x%08x)" % (banner, error_name, call_status))
            return False
        else:
            logging.debug("%s - OK" % banner)
            return True

    def __prepare_path_and_share(self, path, share, isfile=True, double_escape=False):
        # Only for C$, we change the sharename for C:, to make the default dploot
        # work without touching the code to much.
        if share == "C$":
            share = "C:"

        # Adapt path to be compatible with WMI Queries
        if isfile:
            path = f"\\{path}"
        else:
            path = f"\\{path}\\"    
        if double_escape:
            path = path.replace("\\", "\\\\")
        return path, share
    
    def __get_hive_to_wmihive(self, hive:str) -> bytes:
        if hive.lower() == "hkcr":
            return 0x80000000
        elif hive.lower() == "hkcu":
            return 0x80000001
        elif hive.lower() == "hklm":
            return 0x80000002
        elif hive.lower() == "hku":    
            return 0x80000003
        elif hive.lower() == "hkcc":
            return 0x80000005
        else:
            raise ValueError(f"Unknown hive {hive}")
        
    def __get_wmi_stdregprov_instance(self):
        descriptor, _ = self.default_namespace.GetObject("StdRegProv")
        return descriptor.SpawnInstance()
    
    # Common protocol functions

    def connect(self) -> bool:
        try:
            logging.debug("Connecting to %s through WMI" % self.target.address)
            logging.debug(
                f"Authenticating with {self.target.username} through {'Kerberos' if self.target.do_kerberos else 'NTLM'}")
            self.dcom = DCOMConnection(
                target=self.target.address,
                username=self.target.username,
                password=self.target.password,
                domain=self.target.domain,
                lmhash=self.target.lmhash,
                nthash=self.target.nthash,
                aesKey=self.target.aesKey,
                kdcHost=self.target.kdcHost,
                doKerberos=self.target.use_kcache,
            )
            self.iInterface = self.dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            self.iWbemLevel1Login = wmi.IWbemLevel1Login(self.iInterface)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
            return False
        return True
    
    def is_admin(self) -> bool:
        return True # TODO c'est pour le debug

    def list_dir(self, path, share:str="C:", wildcard=True) -> list[SharedFile]:
        if not wildcard:
            raise NotImplementedError("Not implemented for wildcard == False")

        path, share = self.__prepare_path_and_share(path, share, isfile=False, double_escape=True)
        records = []

        # There is no WMI class that allow to query dirs AND files at the same time, so
        # we must do it separatly
        for wmi_table in ["Win32_Directory", "CIM_DataFile"]:
            dirs_query = f'SELECT CreationDate, LastAccessed, LastModified, FileSize, FileType, FileName FROM {wmi_table} WHERE Path = "{path}" AND Drive = "{share}"'
            enum_wbem_class_obj = self.execute_wmi_query(dirs_query)
            finished = False
            while not finished:
                try:
                    class_object = enum_wbem_class_obj.Next(0xffffffff,1)[0]
                    record_props = {a:b["value"] for a,b in dict(class_object.getProperties()).items()}
                    record_attribs = 0
                    if record_props["FileType"] == "File Folder":
                        record_attribs |= ATTR_DIRECTORY 
                    records.append(SharedFile(
                        ctime=record_props["CreationDate"],
                        atime=record_props["LastAccessed"],
                        mtime=record_props["LastModified"],
                        wtime=record_props["LastModified"],
                        filesize=record_props["FileSize"],
                        allocsize=0,
                        attribs=record_attribs,
                        shortname=record_props["FileName"],
                        longname=record_props["FileName"],
                        ))
                except wmi.DCERPCSessionError as e:
                    if e.error_code == 1:
                        finished = True
                    else:
                        logging.debug(str(e))
        return records
    
    def read_file(
        self,
        path,
        share:str="C$",
        looted_files=None,
        bypass_shared_violation=False,
    ) -> bytes:
        if bypass_shared_violation:
            logging.error("bypass_shared_violation is not supported yet in WMI protocol")
        if share != "": # not a UNC path
            path, share = self.__prepare_path_and_share(path, share)
        fullpath = f"{share}{path}"
        escaped_path = fullpath.replace("\\", "\\\\")
        object_path = f'PS_ModuleFile.InstanceID="{escaped_path}"'

        logging.debug(object_path)
        try:
            iWbemClassObject, _ = self.pwshellv3_namespace.GetObject(object_path)
        except wmi.DCERPCSessionError as e:
            if e.error_code == 0x80041002:
                logging.debug(f"Cannot find {fullpath} file")
            return None

        obj = iWbemClassObject.getProperties()

        file_data = None
        for prop_name, prop_value in obj.items():
            if prop_name == "FileData":
                file_data = prop_value["value"]
                break
        
        if len(file_data) < 4:
            return None
          
        file_length = struct.unpack(">I", bytes(file_data[0:4]))[0]
        file_content = bytes(file_data[4:4 + file_length])
        
        logging.debug(f"Read {file_length} bytes from {fullpath}")
        
        if looted_files is not None and file_content is not None and file_content != b"":
            looted_files[os.path.join(*(path.split("\\")))]=file_content

        return file_content
    
    def reg_enum_key(self, hive:str, path:str) -> List[str]:
        ret = self.__get_wmi_stdregprov_instance().EnumKey(self.__get_hive_to_wmihive(hive),path)
        return ret.sNames
    
    def reg_enum_values(self, hive:str, keypath:str) -> List[str]:
        desc = self.__get_wmi_stdregprov_instance()
        ret = desc.EnumValues(self.__get_hive_to_wmihive(hive),keypath)
        return ret.sNames

    def reg_get_key_value(self, hive:str, keypath:str, value_name:str) -> Any:
        value = None
        desc = self.__get_wmi_stdregprov_instance()
        ret = desc.EnumValues(self.__get_hive_to_wmihive(hive),keypath)
        if ret.sNames is None:
            return None
        try:
            index = ret.sNames.index(value_name)
        except Exception as e:
            logging.debug(f"Exception in WMI reg_get_key_value({hive},{keypath},{value_name}): {e})")
            return None
        if ret.Types[index] in [1,2]: # REG_SZ | REG_EXPAND_SZ
            value = desc.GetStringValue(self.__get_hive_to_wmihive(hive),keypath,value_name).sValue
        elif ret.Types[index] == 3: # REG_BINARY 
            value = bytes(desc.GetBinaryValue(self.__get_hive_to_wmihive(hive),keypath,value_name).uValue)
        elif ret.Types[index] == 4: # REG_DWORD
            value = bytes(desc.GetDWORDValue(self.__get_hive_to_wmihive(hive),keypath,value_name).uValue)
        else:
            raise ValueError(f"reg_get_key_value does not supports type {ret.Types[index]}")
        
        return value
    
    def get_dpapi_system_keys(self, looted_files=None) -> Dict[str,bytes]:
        raise NotImplementedError("get_dpapi_system_keys is not implemented in pure WMI (yet)")
        dpapiSystem = {}

        # Creating Shadow Volumes
        win32_shadow_copy,_ = self.cimv2_namespace.GetObject("Win32_ShadowCopy")
        logging.debug("Trying to create SS remotely via WMI")
        result = win32_shadow_copy.Create("C:\\", "ClientAccessible")
        shadow_id = result.ShadowID
        logging.debug(f"Shadow Copy created at ID {shadow_id}")
        
        # Finding it on disk
        iEnum_shadow_copies = self.cimv2_namespace.ExecQuery(f'SELECT DeviceObject FROM Win32_ShadowCopy WHERE ID = "{shadow_id}"')
        obj = iEnum_shadow_copies.Next(0xffffffff, 1)[0]
        props = obj.getProperties()
        shadow_copy = {k: v["value"] for k, v in props.items()}
        logging.debug(f"Found ShadowCopy at {shadow_copy['DeviceObject']}")
            
        # Get the SECURITY
        security_hive_path = f"{shadow_copy['DeviceObject']}\\Windows\\System32\\config\\SECURITY"
        security_hive = self.read_file(security_hive_path, "", looted_files=looted_files)
        if security_hive is not None:
            logging.debug("Got SECURITY hive")
        
        # Delete the dirty stuff
        wmiPath = f'Win32_ShadowCopy.ID="{shadow_id}"'
        logging.debug(f"Trying to delete ShadowCopy with ID {shadow_id}")
        ret = self.cimv2_namespace.DeleteInstance(wmiPath)
        if not self.__check_error("Deleting Shadow Copy",ret):
            logging.error("You will need to delete this by yourself.")

        # Get bootkey
        bootKey = b""
        for key in ["JD","Skew1","GBG","Data"]:
            # Actually, there is no way in pure WMI to request these key class values 
            # We could dump the SYSTEM hive the same way we dump the SECURITY
            # But the WMI download technique is really unefficient, and as the SYSTEM hive
            # is heavy (multiple Mo), this won't work
            import sys
            sys.exit(0)

        # Parse the hives

        return dpapiSystem

    # Namespaces

    @property
    def default_namespace(self) -> wmi.IWbemServices:
        if self._default_namespace is not None:
            return self._default_namespace
        self._default_namespace = self.get_namespace("//./root/default")
        return self._default_namespace

    @property
    def cimv2_namespace(self) -> wmi.IWbemServices:
        if self._cimv2_namespace is not None:
            return self._cimv2_namespace
        self._cimv2_namespace = self.get_namespace("//./root/cimv2")
        return self._cimv2_namespace
    
    @property
    def pwshellv3_namespace(self) -> wmi.IWbemServices:
        if self._pwshellv3_namespace is not None:
            return self._pwshellv3_namespace
        self._pwshellv3_namespace = self.get_namespace("//./root/Microsoft/Windows/Powershellv3")
        return self._pwshellv3_namespace
    
    @property
    def managementtools_namespace(self) -> wmi.IWbemServices:
        if self._managementtools_namespace is not None:
            return self._managementtools_namespace
        self._managementtools_namespace = self.get_namespace("//./root/Microsoft/Windows/ManagementTools")
        return self._managementtools_namespace
    
class DPLootWmiExec:
    def __init__(self, target: Target = None):
        self.__username = target.username
        self.__password = target.password
        self.__domain = target.domain
        self.__lmhash = target.lmhash
        self.__nthash = target.nthash
        self.__aesKey = target.aesKey
        self.__addr = target.address
        self.__kdcHost = target.kdcHost
        self.__doKerberos = target.do_kerberos

        self.__share = "C$"
        self.__pwd = "C:\\"
        self.output = str(time.time())
        self.__win32Process = None

    def run(self, command):
        if logging.getLogger().level != logging.DEBUG:
            logging.getLogger("impacket").disabled = True
        dcom = DCOMConnection(
            self.__addr,
            self.__username,
            self.__password,
            self.__domain,
            self.__lmhash,
            self.__nthash,
            self.__aesKey,
            oxidResolver=True,
            doKerberos=self.__doKerberos,
            kdcHost=self.__kdcHost,
        )
        try:
            iInterface = dcom.CoCreateInstanceEx(
                wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login
            )
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()
            self.__win32Process, _ = iWbemServices.GetObject("Win32_Process")
            self.execute_remote(command)
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        dcom.disconnect()

    def execute_remote(self, command):
        self.__win32Process.Create(command, self.__pwd, None)

class WMITarget(Target):
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

        return WMITarget.create(
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
        self = WMITarget()
        self.protocol = "wmi"

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
            dc_ip = target

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
        group = parser.add_argument_group("wmi authentication")
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
        return DPLootWMIConnection(self)