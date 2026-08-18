import logging
from typing import Any, Dict, List

from impacket.smb import SharedFile

from dploot.lib.target import Target
from dploot.lib.consts import FalsePositives

class DPLootConnection:
    # The generic class for DPLoot Connection. Any method called outside of the class
    # should be implemented here first
    
    def __init__(self, target: Target, false_positive: List[str] | None = None) -> None:
        self.target = target
        self.false_positive = FalsePositives(false_positive)

    def list_dirs(self, share: str, dirlist: List[str]) -> Dict[str, Any]:
        result = {}
        for path in dirlist:
            tmp = self.list_dir(path=path, share=share)
            result[path] = tmp
        return result
    
    def list_users(self):
        directories = self.list_dir(path="Users")
        return [d.get_longname() for d in directories if d.get_longname() not in self.false_positive and d.is_directory() > 0]
    
    def print_connected_info(self) -> None:
        logging.info(
                "Connected to {} as {}\\{}{} through {} connection {}\n".format(
                    self.target.address,
                    self.target.domain,
                    self.target.username,
                    (" with kerberos" if self.target.do_kerberos else " with NTLM"),
                    self.target.protocol.upper(),
                    ("(admin)" if self.is_admin() else ""),
                )
            )
    
    def print_connection_error(self) -> None:
        logging.error(f"Could not connect to {self.target.address} with {self.target.protocol.upper()}")
    
    # The following functions should be implemented by every protocol if possible
    
    def connect(self) -> bool:
        raise NotImplementedError(f"connect function is not implemented for {self.__class__.__name__}")

    def list_dir(self, path, share, wildcard=True) -> list[SharedFile]:
        raise NotImplementedError(f"list_dir function is not implemented for {self.__class__.__name__}")
    
    def is_admin(self) -> bool:
        raise NotImplementedError(f"is_admin function is not implemented for {self.__class__.__name__}")

    def read_file(
        self,
        path,
        share,
        looted_files=None,
        *args, **kwargs
    ) -> bytes:
        raise NotImplementedError(f"read_file function is not implemented for {self.__class__.__name__}")

    def reg_enum_key(self, hive:str, path:str) -> List[str]:
        raise NotImplementedError(f"reg_enum_key function is not implemented for {self.__class__.__name__}")

    def reg_enum_values(self, hive:str, keypath:str) -> List[str]:
        raise NotImplementedError(f"reg_enum_values function is not implemented for {self.__class__.__name__}")
    
    def reg_get_key_value(self, hive:str, keypath:str, value_name:str) -> Any:
        raise NotImplementedError(f"reg_get_key_values function is not implemented for {self.__class__.__name__}")
    
    def get_dpapi_system_keys(self, looted_files=None) -> Dict[str,bytes]:
        raise NotImplementedError(f"get_dpapi_system_keys function is not implemented for {self.__class__.__name__}")
