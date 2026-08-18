import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.utils import dump_looted_files_to_disk

from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.vaults import VaultsTriage


NAME = "machinevaults"


class MachineVaultsAction(DPLootAction):
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

            def secret_callback(vault):
                if self.options.quiet:
                    vault.dump_quiet()
                else:
                    vault.dump()

            vaults_triage = VaultsTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_vault_callback=secret_callback,
            )
            logging.info("Triage SYSTEM Vaults\n")
            vaults_triage.triage_system_vaults()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, vaults_triage.looted_files)

        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = MachineVaultsAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump system vaults from local or remote target"
    )

    group = subparser.add_argument_group("machinevaults options")

    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
