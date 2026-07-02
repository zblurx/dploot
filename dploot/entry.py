import argparse
import importlib.metadata
import logging
import sys
import traceback

from impacket.examples import logger

from dploot.action import (
    backupkey,
    blob,
    browser,
    certificates,
    cng,
    credentials,
    machinecertificates,
    machinecng,
    machinecredentials,
    machinemasterkeys,
    machinetriage,
    machinevaults,
    masterkeys,
    mobaxterm,
    rdg,
    sccm,
    triage,
    vaults,
    wam,
    wifi,
)

ENTRY_PARSERS = [
    backupkey,
    blob,
    browser,
    certificates,
    cng,
    credentials,
    machinecertificates,
    machinecng,
    machinecredentials,
    machinemasterkeys,
    machinetriage,
    machinevaults,
    masterkeys,
    mobaxterm,
    rdg,
    sccm,
    triage,
    vaults,
    wam,
    wifi,
]

def get_network_protocol(argv: list[str]) -> str:
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--protocol", default="smb")
    ns, _ = pre.parse_known_args(argv)
    return ns.protocol

def main(argv=None) -> None:
    logger.init()
    version = importlib.metadata.version("dploot")
    print(f"dploot (https://github.com/zblurx/dploot) v{version} by @_zblurx")

    # Hacky way to get the network protocol before Argparse is called
    # allowing to dynamically set the argparse supported paramater
    argv = argv if argv is not None else sys.argv[1:]
    protocol = get_network_protocol(argv)

    parser = argparse.ArgumentParser(
        description="DPAPI looting in Python",
        add_help=False,
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    actions = {}

    for entry_parser in ENTRY_PARSERS:
        action, entry = entry_parser.add_subparser(subparsers, protocol)
        actions[action] = entry

    options,remaining = parser.parse_known_args()

    if len(sys.argv) == 1:
        sub = subparsers.choices[options.action]
        sub.print_help()
        sys.exit(1)

    if remaining:
        # Little hack to reparse the dynamically addded protocol arguments
        options = parser.parse_args()
    

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    elif options.quiet is True:
        logging.getLogger().setLevel(logging.CRITICAL)
    else:
        logging.getLogger().setLevel(logging.INFO)

    logging.debug(f"{options=}")
    try:
        actions[options.action](options)
    except Exception as e:
        logging.error("Got error: %s" % e)
        if options.debug:
            traceback.print_exc()
        else:
            logging.error("Use -debug to print a stacktrace")

if __name__ == "__main__":
    main()
