import argparse
import logging
import sys
from typing import Dict, Tuple

from dploot.lib.target import Target
from dploot.lib.utils import handle_outputdir_option, parse_file_as_dict
from dploot.triage.masterkeys import parse_masterkey_file


class DPLootAction:
    def init(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)
        self.conn = None

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

        self.pvkbytes, self.passwords, self.nthashes = self.parse_masterkeys_options(
            self.options, self.target
        )

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
        options: argparse.Namespace, target: Target
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

        if target.password is not None and target.password != "":
            if passwords is None:
                passwords = {}
            passwords[target.username] = target.password

        if target.nthash is not None and target.nthash != "":
            if nthashes is None:
                nthashes = {}
            nthashes[target.username] = target.nthash.lower()

        if nthashes is not None:
            nthashes = {k.lower(): v.lower() for k, v in nthashes.items()}

        if passwords is not None:
            passwords = {k.lower(): v for k, v in passwords.items()}

        return pvkbytes, passwords, nthashes