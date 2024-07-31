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
    credentials,
    machinecertificates,
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
    credentials,
    machinecertificates,
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


def main() -> None:
    logger.init()
    version = importlib.metadata.version("dploot")
    print(f"dploot (https://github.com/zblurx/dploot) v{version} by @_zblurx")
    parser = argparse.ArgumentParser(
        description="DPAPI looting locally remotely in Python",
        add_help=True,
    )

    subparsers = parser.add_subparsers(help="Action", dest="action", required=True)

    actions = {}

    for entry_parser in ENTRY_PARSERS:
        action, entry = entry_parser.add_subparser(subparsers)
        actions[action] = entry

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

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
