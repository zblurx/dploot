import argparse
import logging
from binascii import hexlify
from typing import Callable, Tuple

from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.smb import DPLootSMBConnection
from dploot.triage.backupkey import BackupkeyTriage

NAME = 'backupkey'

class BackupkeyAction:
    
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options
        self.target = Target.from_options(options)
        
        self.conn = None
        self._is_admin = None
        self.dce = None
        self.outputfile = None
        self.legacy = self.options.legacy

        if self.options.outputfile is not None and self.options.outputfile != '':
            self.outputfile = self.options.outputfile
        else:
            self.outputfile = 'key.pvk'

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        self.conn.connect()

    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s\n" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        triage = BackupkeyTriage(target=self.target, conn=self.conn)
        backupkey = triage.triage_backupkey()
        if backupkey.backupkey_v1 is not None and self.legacy:
            if not self.options.quiet:
                print("Legacy key:")
                print("0x%s" % hexlify(backupkey.backupkey_v1).decode('latin-1'))
                print("\n")
            logging.info("Exporting key to file {}".format(self.outputfile  + ".key"))
            open(self.outputfile + ".key", 'wb').write(backupkey.backupkey_v1)
        if not self.options.quiet:
            print("[DOMAIN BACKUPKEY V2]")
            backupkey.pvk_header.dump()
            print("PRIVATEKEYBLOB:{%s}" % (hexlify(backupkey.backupkey_v2).decode('latin-1')))
            print("\n")
        logging.critical("Exporting domain backupkey to file {}".format(self.outputfile ))
        open(self.outputfile, 'wb').write(backupkey.backupkey_v2)

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin

def entry(options: argparse.Namespace) -> None:
    a = BackupkeyAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(NAME, help="Backup Keys from domain controller")

    group = subparser.add_argument_group("backupkey options")

    group.add_argument(
        "-outputfile",
        action="store",
        help=(
            "Export keys to specific filename (default key.pvk)"
        ),
    )

    group.add_argument(
        '-legacy',
        action='store_true',
        help=(
            "Get also backupkey v1 (legacy)"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry