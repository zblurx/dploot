import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.triage.backupkey import BackupkeyTriage

NAME = "backupkey"


class BackupkeyAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init(options)
        self.outputfile = None
        self.legacy = self.options.legacy

        if self.options.outputfile is not None and self.options.outputfile != "":
            self.outputfile = self.options.outputfile
        else:
            self.outputfile = "key.pvk"

    def run(self) -> None:
        super().run()
        triage = BackupkeyTriage(target=self.target, conn=self.conn)
        backupkey = triage.triage_backupkey()
        if not self.options.quiet:
            backupkey.dump()
        
        if self.legacy:
            if not self.options.quiet:
                logging.critical("Exporting legacy key to file {}.legacy".format(self.outputfile))
            open(self.outputfile + ".legacy", "wb").write(backupkey.backupkey_v1)
        
        if not self.options.quiet:
            logging.critical(
                f"Exporting domain backupkey to file {self.outputfile}"
            )
        open(self.outputfile, "wb").write(backupkey.backupkey_v2)

def entry(options: argparse.Namespace) -> None:
    a = BackupkeyAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Backup Keys from domain controller")

    group = subparser.add_argument_group("backupkey options")

    group.add_argument(
        "-outputfile",
        action="store",
        help=("Export keys to specific filename (default key.pvk)"),
    )

    group.add_argument(
        "-legacy", action="store_true", help=("Get also backupkey v1 (legacy)")
    )

    add_target_argument_group(subparser, multiproto_support=False)

    return NAME, entry
