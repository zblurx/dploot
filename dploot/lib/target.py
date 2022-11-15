import argparse

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

    @staticmethod
    def from_options(options) -> "Target":
        self = Target()

        username = options.username

        domain = options.domain

        if domain is None:
            domain = ""

        password = options.password
        if (
            not password
            and username != ""
            and options.hashes is None
            and options.aes is None
            and options.no_pass is not True
            and options.do_kerberos is not True
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
            options.dc_ip = options.target

        self.domain = domain
        self.username = username
        self.password = password
        self.address = options.target
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = options.k or options.aesKey is not None or options.use_kcache
        self.kdcHost = options.kdcHost
        self.use_kcache = options.use_kcache
        self.dc_ip = options.dc_ip
        self.aesKey = options.aesKey
        return self

    @staticmethod
    def create(domain: str = None,
        username: str = None,
        password: str = None,
        target: str = None,
        hashes: str = None,
        lmhash: str = None,
        nthash: str = None,
        do_kerberos: bool = False, 
        kdcHost: str = None, 
        use_kcache: bool = False,
        no_pass: bool = False,
        dc_ip: str = None,
        aesKey: str = None) -> "Target":

        self = Target()

        if domain is None:
            domain = ""

        if (
            not password
            and username != ""
            and hashes is None
            and aesKey is None
            and no_pass is not True
            and do_kerberos is not True
        ):
            from getpass import getpass

            password = getpass("Password:")

        if hashes is not None:
            hashes = hashes.split(':')
            if len(hashes) == 1:
                (nthash,) = hashes
                lmhash = nthash
            else:
                lmhash, nthash = hashes
        elif lmhash is None and nthash is None:
            lmhash = nthash = ''
        
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
        return self

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)

def add_target_argument_group(parser: argparse.ArgumentParser,) -> None:

    parser.add_argument(
        "target",
        action="store",
        metavar="<target name or address>",
        help="Target ip or address",
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