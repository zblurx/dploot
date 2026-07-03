import argparse
import logging
from binascii import unhexlify

from typing import Any, Optional

from impacket import tds
from impacket.smb import SharedFile, ATTR_DIRECTORY

from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target


class DPLootMSSQLConnection(DPLootConnection):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.conn = None

    def __create_conn_obj(self):
        try:
            self.conn = tds.MSSQL(self.target.address, self.target.port, self.target.address)
            self.conn.connect()
        except Exception as e:
            logging.debug(f"Error connecting to MSSQL service on host: {self.target.address}, reason: {e}")
            self.conn.disconnect()
            return False
        else:
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
            path = f"\\{path}"    
        if double_escape:
            path = path.replace("\\", "\\\\")
        return path, share

    def __get_hive_to_mssqlhive(self, hive:str) -> bytes:
        if hive.lower() == "hklm":
            return "HKEY_LOCAL_MACHINE"
        elif hive.lower() == "hku":    
            return "HKEY_USERS"
        else:
            raise ValueError(f"Unknown hive {hive}")
    
    def execute_query(self, query:str) -> Any:
        logging.debug(f"Executing query: {query}")
        self.conn.sql_query(query)
        return self.conn.rows


    def connect(self) -> bool:
        res = False
        try:
            logging.debug("Connecting to %s through MSSQL" % self.target.address)
            if not self.__create_conn_obj():
                    return False
            if self.target.do_kerberos:
                res = self.conn.kerberosLogin(
                    database=None,
                    username=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    hashes=self.target.hashes,
                    aesKey=self.target.aesKey,
                    kdcHost=self.target.kdcHost,
                    useCache=self.target.use_kcache,
                )
            else:
                res = self.conn.login(
                    database=None,
                    username=self.target.username,
                    password=self.target.password,
                    domain=self.target.domain,
                    hashes=self.target.hashes,
                    useWindowsAuth=not self.target.db_auth
                )
            
        except Exception:
            import traceback
            traceback.print_exc()
        return res

    def is_admin(self) -> bool:
        try:
            results = self.conn.sql_query("SELECT IS_SRVROLEMEMBER('sysadmin')")
            is_admin = int(results[0][""])
            return is_admin
        except Exception as e:
            logging.error(f"Error querying for sysadmin role: {e}")

    def list_dir(self, path, share:str="C:", wildcard=True) -> list[SharedFile]:
        if not wildcard:
            raise NotImplementedError("Not implemented for wildcard == False")
        
        path, share = self.__prepare_path_and_share(path, share, isfile=False, double_escape=True)
        fullpath = f"{share}{path}"
        records = []

        try:  
            for row in self.execute_query(f"SELECT file_or_directory_name, size_in_bytes, is_directory, creation_time, last_access_time, last_write_time FROM sys.dm_os_enumerate_filesystem('{fullpath}', '*') WHERE level = 0"):
                record_attribs = 0
                if row["is_directory"]:
                    record_attribs |= ATTR_DIRECTORY 
                records.append(SharedFile(
                    ctime=row["creation_time"],
                    atime=row["last_access_time"],
                    mtime=row["last_write_time"],
                    wtime=row["last_write_time"],
                    filesize=row["size_in_bytes"],
                    allocsize=0,
                    attribs=record_attribs,
                    shortname=row["file_or_directory_name"],
                    longname=row["file_or_directory_name"],
                    ))
        except Exception as e:
            logging.debug(f"Error listing directory {fullpath}: {e}")
        return records

    def read_file(
        self,
        path,
        share:str="C:",
        looted_files=None,
        bypass_shared_violation=False,
    ) -> bytes:
        if bypass_shared_violation:
            logging.error("bypass_shared_violation is not supported yet in MSSQL protocol")
        if share != "": # not a UNC path
            path, share = self.__prepare_path_and_share(path, share)
        fullpath = f"{share}{path}"
        try:
            data = self.execute_query(f"SELECT * FROM OPENROWSET(BULK N'{fullpath}', SINGLE_BLOB) rs")
            if len(data) > 0:
                return unhexlify(data[0]["BulkColumn"])
        except Exception as e:
            logging.debug(f"Exception while downloading file {fullpath}: {e}")
            return None
        return None

class MSSQLTarget(Target):
    def __init__(self) -> None:
        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.address: str = None
        self.port: str = None
        self.hashes: str = None
        self.do_kerberos: bool = False
        self.kdcHost: str = None
        self.use_kcache: bool = False
        self.dc_ip: str = None
        self.aesKey: str = None
        self.db_auth: bool = False

    @staticmethod
    def from_options(options) -> "Target":
        if options.dc_ip is None:
            options.dc_ip = options.target

        return MSSQLTarget.create(
            domain=options.domain,
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            address=options.target,
            port=options.port,
            hashes=options.hashes,
            do_kerberos=options.k or options.aesKey is not None or options.use_kcache,
            kdcHost=options.kdcHost,
            use_kcache=options.use_kcache,
            no_pass=options.no_pass,
            dc_ip=options.dc_ip,
            aesKey=options.aesKey,
            db_auth=options.db_auth,
        )

    @staticmethod
    def create(
        domain: Optional[str] = None,
        username: str = "",
        password: str = "",
        address: Optional[str] = None,
        port: str = "",
        hashes: Optional[str] = None,
        do_kerberos: bool = False,
        kdcHost: Optional[str] = None,
        use_kcache: bool = False,
        no_pass: bool = False,
        dc_ip: Optional[str] = None,
        aesKey: Optional[str] = None,
        db_auth: bool = False
    ) -> "Target":
        self = MSSQLTarget()
        self.protocol = "mssql"

        if domain is None:
            domain = ""

        if dc_ip is None:
            dc_ip = target

        self.domain = domain
        self.username = username
        self.password = password
        self.address = address
        self.port = port
        self.hashes = hashes
        self.do_kerberos = do_kerberos or aesKey is not None or use_kcache
        self.kdcHost = kdcHost
        self.use_kcache = use_kcache
        self.dc_ip = dc_ip
        self.aesKey = aesKey
        self.db_auth = db_auth

        return self

    @staticmethod
    def add_network_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
        group = parser.add_argument_group("mssql authentication")
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
            default="1433",
            help="MSSQL target port (default: 1434)",
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
        group.add_argument(
            "--db-auth",
            action="store_true",
            help="Use Local MSSQL Database Authentication",
        )

    def create_connection_object(self):
        return DPLootMSSQLConnection(self)