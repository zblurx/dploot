from abc import ABC, abstractmethod
from typing import List, Dict, Callable, Any

from dploot.lib.target import Target
from dploot.lib.network import DPLootConnection
from dploot.triage.masterkeys import Masterkey
from dploot.lib.consts import FalsePositives

# Define base triage class.

class Triage:
    """
    Class Definition for the DPLoot Triage Class.
    """
    def __init__(
        self,
        target: Target,
        conn: DPLootConnection,
        masterkeys: List[Masterkey] = None,
        per_loot_callback: Callable = None,
        false_positive: List[str] | None = None,
    ) -> None:
        
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.per_loot_callback = per_loot_callback
        self.false_positive = FalsePositives(false_positive)

        self.looted_files = {}
        self._users = None

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users()

        return self._users
