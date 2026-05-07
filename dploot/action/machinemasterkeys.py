import argparse
from binascii import unhexlify
import logging
import sys
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "machinemasterkeys"


class MachineMasterkeysAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init(options)
        self.outputfile = None
        self.outputdir = None
        self.dpapi_system_key = {}

        if self.options.dpapi_system_key is not None and self.options.dpapi_system_key != "":
            correl_table = {"dpapi_machinekey":"MachineKey","dpapi_userkey":"UserKey"}
            self.dpapi_system_key = {correl_table[k] :unhexlify(v[2:]) for k, v in (elem.split(":") for elem in options.dpapi_system_key.split(","))}

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.outputfile is not None and self.options.outputfile != "":
            self.outputfile = self.options.outputfile

    def run(self) -> None:
        super().run()
        if self.conn.is_admin():
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
