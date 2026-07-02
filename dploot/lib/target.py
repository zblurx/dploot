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