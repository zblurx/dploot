from abc import ABC, abstractmethod
from typing import List, Dict, Callable, Any

from dploot.lib.target import Target
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.masterkey import Masterkey
from dploot.lib.consts import FALSE_POSITIVES

# simple class to check for false positive case insensitive
class FalsePositive:
    def __init__(self,
                 false_positive: List[str] = FALSE_POSITIVES
    ) -> None:
        self.false_positive = list(map(lambda x:str(x).lower(), false_positive))

    def contains(self, name):
        return str(name).lower() in self.false_positive

# Define base triage class.

class Triage:
    """
    Class Definition for the DPLoot Triage Class.
    """
    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey] = None,
        per_loot_callback: Callable = None,
        false_positive: List[str] = FALSE_POSITIVES,
    ) -> None:
        
        self.target = target
        self.conn = conn
        self.masterkeys = masterkeys
        self.per_loot_callback = per_loot_callback
        self.false_positive = FalsePositive(false_positive)

        self.looted_files = {}
