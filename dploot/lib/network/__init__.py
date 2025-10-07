import logging
# from dploot.lib.network.connection import DPLootConnection
# from dploot.lib.network.local import DPLootLocalConnection
# from dploot.lib.network.smb import DPLootSMBConnection
from dploot.lib.target import Target


## check

import logging
from typing import Any, Dict, List

from dploot.lib.target import Target
from dploot.lib.consts import FalsePositives

class DPLootConnection:
    # if called with target = LOCAL, return an instance of DPLootLocalSMConnection,
    # else return an instance of DPLootRemoteSMBConnection
    
    def __init__(self, target: Target, false_positive: List[str] | None = None) -> None:
        self.target = target
        self.remote_ops = None
        self.local_session = None

        self._usersProfiles = None

        self.false_positive = FalsePositives(false_positive)

    def listDirs(self, share: str, dirlist: List[str]) -> Dict[str, Any]:
        result = {}
        for path in dirlist:
            tmp = self.remote_list_dir(share, path=path)
            result[path] = tmp
        return result
    
##

