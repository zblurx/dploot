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
        self.target = Target(options)

        self.conn = None
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

        triage = BackupkeyTriage(target=self.target, conn=self.conn)
        triage.triage_backupkey()
        if triage.backupkey_v1 is not None and self.legacy:
            print("Legacy key:")
            print("0x%s" % hexlify(triage.backupkey_v1).decode('latin-1'))
            print("\n")
            logging.info("Exporting key to file {}".format(self.outputfile  + ".key"))
            open(self.outputfile + ".key", 'wb').write(triage.backupkey_v1)
        print("[DOMAIN BACKUPKEY V2]")
        triage.pvk_header.dump()
        print("PRIVATEKEYBLOB:{%s}" % (hexlify(triage.backupkey_v2).decode('latin-1')))
        print("\n")
        logging.info("Exporting private key to file {}".format(self.outputfile ))
        open(self.outputfile, 'wb').write(triage.backupkey_v2)

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