import logging
import hashlib
import argparse
import base64
import xml.etree.ElementTree as ET
from typing import Any, List, Optional

from impacket.smb import SharedFile, ATTR_DIRECTORY

from pypsrp.wsman import NAMESPACES
from pypsrp.client import Client
from pypsrp._utils import get_pwsh_script
from pypsrp.powershell import (
    DEFAULT_CONFIGURATION_NAME,
    PowerShell,
    RunspacePool,
)

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target

class DPLootWINRMConnection(DPLootConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        logging.getLogger("pypsrp").setLevel(logging.ERROR)
        self.conn = None

    def __prepare_path_and_share(self, path, share, isfile=True, double_escape=False):
        # Only for C$, we change the sharename for C:, to make the default dploot
        # work without touching the code to much.
        if share == "C$":
            share = "C:"

        # Adapt path to be compatible with WMI Queries
        if isfile:
            path = f"\\{path}"
        else:
            path = f"\\{path}"    
        if double_escape:
            path = path.replace("\\", "\\\\")
        return path, share

    def execute_ps(self, command):
        logging.debug(f"Executing Powershell command: {command}")
        result = self.conn.execute_ps(command)
        return result[0].splitlines()

    def print_connected_info(self) -> None:
        logging.info(
                "Connected to {} as {}\\{} through {} connection {}\n".format(
                    self.target.address,
                    self.target.domain,
                    self.target.username,
                    self.target.protocol.upper(),
                    ("(admin)" if self.is_admin() else ""),
                )
            )

    def connect(self) -> bool:
        logging.debug("Connecting to %s through WINRM" % self.target.address)
        try:
            password = f"{self.target.lmhash}:{self.target.nthash}" if self.target.nthash != "" else self.target.password
            self.conn = Client(
                server=self.target.address,
                port=self.target.port,
                auth="ntlm",
                username=f"{self.target.domain}\\{self.target.username}",
                password=password,
                ssl=self.target.ssl,
                cert_validation=False,
            )
            return self.is_admin()
            print(dir(self.conn.wsman))
        except Exception as e:
            logging.debug(f"Exception while logging to {self.target.address}: {e}")
            raise
    
    def is_admin(self) -> bool:
        wsman = self.conn.wsman
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        return True
    
    def list_dir(self, path, share:str="C:", wildcard=True) -> list[SharedFile]:
        path, share = self.__prepare_path_and_share(path, share, isfile=False, double_escape=True)
        fullpath = f"{share}{path}"
        records = []
        try:
            results = self.execute_ps(f"Get-ChildItem -Path {fullpath} -Attributes !ReadOnly+Hidden,!ReadOnly | Select-Object Name, PSIsContainer, CreationTime, LastAccessTime, LastWriteTime, Length | ConvertTo-Csv -NoTypeInformation")
            for item in results[1:]:
                name, is_dir, creation_time, last_access_time, last_write_time, size = [e[1:-1] for e in item.split(",")]
                record_attribs = 0
                if is_dir == "True":
                    record_attribs |= ATTR_DIRECTORY
                records.append(SharedFile(
                        ctime=creation_time,
                        atime=last_access_time,
                        mtime=last_write_time,
                        wtime=last_write_time,
                        filesize=size,
                        allocsize=0,
                        attribs=record_attribs,
                        shortname=name,
                        longname=name,
                        ))
        except Exception as e:
            logging.debug(f"Error while listing path {fullpath}: {e}")
        return records

    def read_file(
        self,
        path,
        share:str="C:",
        looted_files=None,
        *args, **kwargs
    ) -> bytes:
        path, share = self.__prepare_path_and_share(path, share, isfile=True, double_escape=True)
        fullpath = f"{share}{path}"
        with RunspacePool(self.conn.wsman, configuration_name=DEFAULT_CONFIGURATION_NAME) as pool:
            try:
                script = get_pwsh_script("fetch.ps1")
                powershell = PowerShell(pool)
                powershell.add_script(script).add_argument(fullpath).add_argument(False)
                logging.debug("Starting remote process to output file data")
                powershell.invoke()
                logging.debug("Finished remote process to output file data")
                
                expected_hash = powershell.output[-1]
                file_bytes = base64.b64decode(powershell.output[0])
                sha1 = hashlib.sha1()
                sha1.update(file_bytes)
                actual_hash = sha1.hexdigest()
                if actual_hash != expected_hash:
                    raise WinRMError(
                        "Failed to fetch file %s, hash mismatch\n"
                        "Source: %s\nFetched: %s" % (src, expected_hash, actual_hash)
                    )
                return file_bytes
            except Exception as e:
                logging.debug(e)
        return None

    def reg_enum_key(self, hive:str, path:str) -> List[str]:
        fullpath = f"{hive.upper()}:{path}"
        results = self.execute_ps(f"Get-ChildItem -Path '{fullpath}'  | Select-Object -ExpandProperty PSChildName")
        return results
    
    def reg_get_key_value(self, hive:str, keypath:str, value_name:str) -> Any:
        fullpath = f"{hive.upper()}:{keypath}"
        results = self.execute_ps(f"(Get-ItemProperty -Path '{fullpath}' -Name '{value_name}').{value_name}")
        
        if isinstance(results,list):
            return bytes(int(x) for x in results)
        return results

class WINRMTarget(Target):
    def __init__(self) -> None:
        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.address: str = None
        self.port: str = None
        self.ssl: bool = False
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.dc_ip: str = None

    @staticmethod
    def from_options(options) -> "Target":
        if options.dc_ip is None:
            options.dc_ip = options.target

        return WINRMTarget.create(
            domain=options.domain,
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            address=options.target,
            port=options.port,
            ssl=options.ssl,
            hashes=options.hashes,
            lmhash=None,
            nthash=None,
            dc_ip=options.dc_ip,
        )

    @staticmethod
    def create(
        domain: Optional[str] = None,
        username: str = "",
        password: str = "",
        address: Optional[str] = None,
        port: Optional[str] = None,
        ssl: bool = False,
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        dc_ip: Optional[str] = None,
    ) -> "Target":
        self = WINRMTarget()
        self.protocol = "winrm"

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
        self.port = port
        self.ssl = ssl
        self.lmhash = lmhash
        self.nthash = nthash
        self.dc_ip = dc_ip

        return self

    @staticmethod
    def add_network_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
        group = parser.add_argument_group("winrm authentication")
        group.add_argument(
            "-t",
            "--target",
            action="store",
            dest="target",
            metavar="<target name or address>",
            help="Target ip or address",
        )

        group.add_argument(
            "--port",
            action="store",
            dest="port",
            metavar="TCP PORT",
            default="5985",
            help="WINRM target port (default: 5985)",
        )

        group.add_argument(
            "--ssl",
            action="store_true",
            dest="ssl",
            help="Connect with SSL (WINRM-SSL)",
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
            "--dc-ip",
            action="store",
            metavar="ip address",
            help=(
                "IP Address of the domain controller. If omitted it will use the domain "
                "part (FQDN) specified in the target parameter"
            ),
        )

    def create_connection_object(self):
        return DPLootWINRMConnection(self)