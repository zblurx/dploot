import argparse
import logging
import sys
from typing import Optional

class Target:
    def __init__(self) -> None:
        self.address: str = None
        self.protocol: str = "smb"

    def __repr__(self) -> str:
        return "<Target (%s)>" % repr(self.__dict__)

    @staticmethod
    def from_options(options) -> "Target":
        raise NotImplementedError(f"function is not implemented for {self.__class__.__name__}")

    @staticmethod
    def create() -> "Target":
        raise NotImplementedError(f"function is not implemented for {self.__class__.__name__}")

    @staticmethod
    def add_network_argument_group(parser: argparse.ArgumentParser):
        raise NotImplementedError(f"function is not implemented for {self.__class__.__name__}")

    def create_connection_object(self):
        raise NotImplementedError(f"function is not implemented for {self.__class__.__name__}")

def get_network_protocol_subparser(parser, protocol: str):
    match protocol:
        case "smb":
            from dploot.lib.network.smb import SMBTarget
            SMBTarget.add_network_argument_group(parser)
        case "wmi":
            from dploot.lib.network.wmi import WMITarget
            WMITarget.add_network_argument_group(parser)
        case "local":
            from dploot.lib.network.local import LocalTarget
            LocalTarget.add_network_argument_group(parser)