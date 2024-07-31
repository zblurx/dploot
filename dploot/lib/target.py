import argparse
import sys
from typing import Optional

from dploot.lib.utils import add_general_args


class Target:
    def __init__(self) -> None:
        self.domain: str = None
        self.username: str = None
        self.password: str = None
        self.address: str = None
        self.hashes: str = None
        self.lmhash: str = None
        self.nthash: str = None
        self.do_kerberos: bool = False
        self.kdcHost: str = None
        self.use_kcache: bool = False
        self.dc_ip: str = None
        self.aesKey: str = None
        self.local_root: str = None
        self.is_local: bool = False

    @staticmethod
    def from_options(options) -> "Target":
        if options.dc_ip is None:
            options.dc_ip = options.target

        return Target.create(
            domain=options.domain,
            username=options.username if options.username is not None else "",
            password=options.password if options.password is not None else "",
            target=options.target,
            hashes=options.hashes,
            lmhash=None,
            nthash=None,
            do_kerberos=options.k or options.aesKey is not None or options.use_kcache,
            kdcHost=options.kdcHost,
            use_kcache=options.use_kcache,
            no_pass=options.no_pass,
            dc_ip=options.dc_ip,
            aesKey=options.aesKey,
            local_root=options.localroot,
        )

    @staticmethod
    def create(
        domain: Optional[str] = None,
        username: str = "",
        password: str = "",
        target: Optional[str] = None,
        hashes: Optional[str] = None,
        lmhash: str = "",
        nthash: str = "",
        do_kerberos: bool = False,
        kdcHost: Optional[str] = None,
        use_kcache: bool = False,
        no_pass: bool = False,
        dc_ip: Optional[str] = None,
        aesKey: Optional[str] = None,
        local_root: Optional[str] = None,
    ) -> "Target":
        self = Target()

        if target == "LOCAL":
            self.is_local = True

        if self.is_local is True:
            if do_kerberos or use_kcache or kdcHost is not None:
                print(
                    "Invalid options: Use kerberos does not make sense when target=LOCAL",
                    file=sys.stderr,
                )
                sys.exit(1)
            if dc_ip is not None and dc_ip != "LOCAL":
                print(
                    "Invalid options: dc-ip conflicts with target=LOCAL",
                    file=sys.stderr,
                )
                sys.exit(1)

        if domain is None:
            domain = ""

        if (
            not password
            and username != ""
            and hashes is None
            and aesKey is None
            and no_pass is not True
            and do_kerberos is not True
            and self.is_local is not True
        ):
            from getpass import getpass

            password = getpass("Password:")

        if hashes is not None:
            hashes = hashes.split(":")
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        elif lmhash is None and nthash is None:
            lmhash = nthash = ""

        if dc_ip is None:
            dc_ip = target

        self.domain = domain
        self.username = username
        self.password = password
        self.address = target
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos or aesKey is not None or use_kcache
        self.kdcHost = kdcHost
        self.use_kcache = use_kcache
        self.dc_ip = dc_ip
        self.aesKey = aesKey
        self.local_root = local_root

        return self

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)


def add_target_argument_group(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument(
        "-t",
        "-target",
        action="store",
        dest="target",
        metavar="<target name or address>",
        help="Target ip or address, or LOCAL",
    )

    parser.add_argument(
        "-d",
        "-domain",
        metavar="domain.local",
        dest="domain",
        action="store",
        help="Domain name",
    )

    parser.add_argument(
        "-u",
        "-username",
        metavar="username",
        dest="username",
        action="store",
        help="Username",
    )

    parser.add_argument(
        "-p",
        "-password",
        metavar="password",
        dest="password",
        action="store",
        help="Password",
    )

    add_general_args(parser)

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument("-k", action="store_true", help="Use Kerberos authentication")
    group.add_argument(
        "-aesKey",
        action="store",
        metavar="hex key",
        help="AES key to use for Kerberos Authentication (128 or 256 bits)",
    )
    group.add_argument(
        "-use-kcache",
        action="store_true",
        help="Use Kerberos authentication from ccache file (KRB5CCNAME)",
    )
    group.add_argument(
        "-kdcHost",
        help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter",
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )
    group.add_argument(
        "-root",
        action="store",
        dest="localroot",
        metavar="path",
        default=".",
        help=(
            "Root directory (for local operations). This directory should contain Windows and Users subdirectories"
        ),
    )
