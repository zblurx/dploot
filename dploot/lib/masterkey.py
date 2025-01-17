import logging
from binascii import hexlify
from Cryptodome.Hash import SHA1

from impacket.dpapi import (
    MasterKeyFile,
    MasterKey,
)

from dploot.lib.dpapi import decrypt_masterkey


class Masterkey:
    def __init__(self, guid, blob = None, sid = None, key = None, sha1 = None, user: str = "None") -> None:
        self.guid = guid
        self.blob = blob
        self.sid = sid
        self.user = user

        self.key = key
        self._sha1 = sha1

        if self.blob is not None:
            self.generate_hash()

    def __str__(self) -> str:
        return f"{{{self.guid}}}:{self.sha1}" if self.key is not None else ""

    def decrypt(self, domain_backupkey = None, password = None, nthash = None, dpapi_systemkey = None) -> bool:
        key = decrypt_masterkey(
            masterkey=self.blob,
            domain_backupkey=domain_backupkey,
            sid=self.sid,
            password=password,
            nthash=nthash,
            dpapi_systemkey=dpapi_systemkey
        )
        if key is not None:
            self.key = key
            return True
        return False
    
    def generate_hash(self):
        hashes = []
        mkf = MasterKeyFile(self.blob)
        data = self.blob[len(mkf) :]
        if mkf["MasterKeyLen"] > 0:
            mk = MasterKey(data[:mkf["MasterKeyLen"]])
            try:
                iteration_count = mk["MasterKeyIterationCount"]
                iv = hexlify(mk["Salt"]).decode("ascii")
                encryted_data = hexlify(mk["data"]).decode("ascii")
                version = 1 if len(encryted_data) == 208 else 2
                hash_algo = "sha1" if len(encryted_data) == 208 else "sha512"
                crypt_algo = "des3" if len(encryted_data) == 208 else "aes256"
                hashes = [f"{self.user}:$DPAPImk${version}*{context}*{self.sid}*{crypt_algo}*{hash_algo}*{iteration_count}*{iv}*{len(encryted_data)}*{encryted_data}"for context in [1,2,3]]    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(e)
        return hashes

    def dump(self) -> None:
        print(self)

    @property
    def sha1(self):
        if self._sha1 is not None:
            return self._sha1
        if self.key is not None:
            try:
                self._sha1 = hexlify(SHA1.new(self.key).digest()).decode("latin-1")
            except Exception as e:
                logging.debug(f"Could not generate sha1 for masterkey {self.guid}: {e}")
        return self._sha1
