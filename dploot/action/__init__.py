import argparse
import logging
import sys
from typing import Dict, Tuple

from dploot.lib.utils import handle_outputdir_option, parse_file_as_dict
from dploot.triage.masterkeys import parse_masterkey_file


class DPLootAction:
    def init(self, options: argparse.Namespace) -> None:
        self.options = options
        self.conn = None

        match self.options.protocol:
            case "smb":
                from dploot.lib.network.smb import SMBTarget
                self.target = SMBTarget.from_options(options)
            case "wmi":
                from dploot.lib.network.wmi import WMITarget
                self.target = WMITarget.from_options(options)
            case "mssql":
                from dploot.lib.network.mssql import MSSQLTarget
                self.target = MSSQLTarget.from_options(options)
            case "local":
                from dploot.lib.network.local import LocalTarget
                self.target = LocalTarget.from_options(options)

    def init_triage_generic(self, options: argparse.Namespace) -> None:
        self.init(options=options)
        self.outputdir = None
        self.masterkeys = None
        self.mkfile = None

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.mkfile is not None:
            self.mkfile = self.options.mkfile
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

    def init_triage_user(self, options: argparse.Namespace) -> None:
        self.init_triage_generic(options=options)
        self.pvkbytes = None
        self.passwords = None
        self.nthashes = None

        self.pvkbytes, self.passwords, self.nthashes = self.parse_masterkeys_options(self.options)

    def connect(self) -> bool:
        self.conn = self.target.create_connection_object()
        return self.conn.connect()

    def run(self) -> None:
        if self.connect():
            self.conn.print_connected_info()
        else:
            logging.error(f"Could not connect to {self.target.address} with {self.target.protocol.upper()}")
            sys.exit(1)

    def parse_masterkeys_options(
        self,
        options: argparse.Namespace
    ) -> Tuple[bytes, Dict[str, str], Dict[str, str]]:
        pvkbytes = None
        passwords = {}
        nthashes = {}
        if hasattr(options, "pvk") and options.pvk is not None:
            try:
                pvkbytes = open(options.pvk, "rb").read()
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        if hasattr(options, "passwords") and options.passwords is not None:
            try:
                passwords = parse_file_as_dict(options.passwords)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        if hasattr(options, "nthashes") and options.nthashes is not None:
            try:
                nthashes = parse_file_as_dict(options.nthashes)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        if hasattr(options, "password") and options.password is not None:
            if passwords is None:
                passwords = {}
            passwords[options.username] = options.password

        if hasattr(options, "nthash") and options.nthash is not None:
            if nthashes is None:
                nthashes = {}
            nthashes[options.username] = options.nthash.lower()

        if nthashes is not None:
            nthashes = {k.lower(): v.lower() for k, v in nthashes.items()}

        if passwords is not None:
            passwords = {k.lower(): v for k, v in passwords.items()}

        return pvkbytes, passwords, nthashes

    @staticmethod
    def get_network_protocol_subparser(parser, protocol: str):
        match protocol:
            case "smb":
                from dploot.lib.network.smb import SMBTarget
                SMBTarget.add_network_argument_group(parser)
            case "wmi":
                from dploot.lib.network.wmi import WMITarget
                WMITarget.add_network_argument_group(parser)
            case "mssql":
                from dploot.lib.network.mssql import MSSQLTarget
                MSSQLTarget.add_network_argument_group(parser)
            case "local":
                from dploot.lib.network.local import LocalTarget
                LocalTarget.add_network_argument_group(parser)

    @staticmethod
    def add_general_args(parser, protocol: str = "smb", supported_protocol = ["smb", "wmi", "mssql", "local"]):
        parser.add_argument("--debug", action="store_true", help="Turn DEBUG output ON")

        parser.add_argument(
            "--quiet", action="store_true", help="Only output dumped credentials"
        )

        parser.add_argument(
            "--export-dir",
            action="store",
            metavar="DIR",
            help=(
                "Dump looted files to specified directory, regardless they were decrypted"
            ),
        )

        parser.add_argument(
            "--protocol",
            action="store",
            metavar="PROTOCOL",
            default=supported_protocol[0],
            choices=supported_protocol,
            help= (
                f"Protocol to use ({', '.join(supported_protocol)}). Default: {supported_protocol[0]}. "
                f"To see helper for other protocol, choose a specific protocol with --protocol and show helper with --help"
            )
        )

        DPLootAction.get_network_protocol_subparser(parser, protocol)
        