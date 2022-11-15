import argparse
from impacket.examples.utils import parse_target

class Target:
    def __init__(self, options) -> None:
        domain, username, password, address = parse_target(options.target)

        if domain is None:
            domain = ""

        if (
            password == ""
            and username != ""
            and options.hashes is None
            and options.no_pass is not True
        ):
            from getpass import getpass

            password = getpass("Password:")
        hashes = options.hashes
        if hashes is not None:
            hashes = hashes.split(':')
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        else:
            lmhash = nthash = ''
        
        if options.dc_ip is None:
            options.dc_ip = address

        self.domain = domain
        self.username = username[:20]
        self.password = password
        self.address = address
        self.lmhash = lmhash
        self.nthash = nthash
        self.ntlmhash = "%s:%s" % (lmhash,nthash)
        self.do_kerberos = options.k or options.aesKey is not None or options.use_kcache
        self.kdcHost = options.kdcHost
        self.use_kcache = options.use_kcache
        self.dc_ip = options.dc_ip
        self.aesKey = options.aesKey

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)

def add_target_argument_group(parser: argparse.ArgumentParser,) -> None:

    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<target name or address>",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    parser.add_argument("-quiet", action="store_true", help="Only output dumped credentials")

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
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument("-use-kcache", action='store_true', help="Use Kerberos authentication from ccache file (KRB5CCNAME)")
    group.add_argument("-kdcHost", help="FQDN of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter")
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )