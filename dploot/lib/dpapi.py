import logging
from typing import Any, Dict, List
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from binascii import unhexlify

from Cryptodome.Util.Padding import unpad
from Cryptodome.Hash import HMAC

from impacket.uuid import bin_to_string
from impacket.dpapi import MasterKeyFile, MasterKey, DomainKey,  DPAPI_BLOB, \
    CREDENTIAL_BLOB, VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS, \
    PVK_FILE_HDR, PRIVATE_KEY_BLOB, ALGORITHMS_DATA, privatekeyblob_to_pkcs1, DPAPI_DOMAIN_RSA_MASTER_KEY, CredentialFile

from dploot.lib.crypto import PRIVATE_KEY_RSA, PVKFile, PVKFile_SIG, PVKHeader, deriveKeysFromUser, deriveKeysFromUserkey, pvkblob_to_pkcs1

def decrypt_masterkey(masterkey:bytes, domain_backupkey:bytes= None, dpapi_systemkey:Dict= None, sid: str = '', password:str = None, nthash:str = None) -> Any:
    if domain_backupkey is None and password is None and nthash is None and dpapi_systemkey is None:
        return None
    data = masterkey
    mkf = MasterKeyFile(data)
    dk = mk = bkmk = None
    data = data[len(mkf):]
    if mkf['MasterKeyLen'] > 0:
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        data = data[len(mk):]

    if mkf['BackupKeyLen'] > 0:
        bkmk = MasterKey(data[:mkf['BackupKeyLen']])
        data = data[len(bkmk):]

    if mkf['DomainKeyLen'] > 0:
        dk = DomainKey(data[:mkf['DomainKeyLen']])
        data = data[len(dk):]

    if domain_backupkey is not None and dk is not None:
        key = PRIVATE_KEY_BLOB(domain_backupkey[len(PVK_FILE_HDR()):])
        private = privatekeyblob_to_pkcs1(key)
        cipher = PKCS1_v1_5.new(private)
        
        decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
        if decryptedKey:
            domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
            key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
            return key

    if sid != '':
        if nthash is not None:
            nthash = unhexlify(nthash)
            key1, key2 = deriveKeysFromUserkey(sid, nthash)
            decryptedKey = mk.decrypt(key2) or mk.decrypt(key1)
            if decryptedKey:
                return decryptedKey
            # decryptedKey = bkmk.decrypt(key2)
            # if decryptedKey:
            #     return decryptedKey
            # decryptedKey = bkmk.decrypt(key1)
            # if decryptedKey:
            #     return decryptedKey
        
        if password is not None:
            key1, key2, key3 = deriveKeysFromUser(sid, password)
            decryptedKey = (
                mk.decrypt(key3)
                or mk.decrypt(key2)
                or mk.decrypt(key1)
            )
            if decryptedKey:
                return decryptedKey
            # decryptedKey = bkmk.decrypt(key3)
            # if decryptedKey:
            #     return decryptedKey
            # decryptedKey = bkmk.decrypt(key2)
            # if decryptedKey:
            #     return decryptedKey
            # decryptedKey = bkmk.decrypt(key1)
            # if decryptedKey:
            #     return decryptedKey

    if dpapi_systemkey is not None:

        decryptedKey = (
            mk.decrypt(dpapi_systemkey['UserKey'])
            or mk.decrypt(dpapi_systemkey['MachineKey'])
            or bkmk.decrypt(dpapi_systemkey['UserKey'])
            or bkmk.decrypt(dpapi_systemkey['MachineKey'])
        )
        if decryptedKey:
            return decryptedKey

        if sid != '':
            test = dpapi_systemkey['UserKey']
            key1, key2 = deriveKeysFromUserkey(sid, test)
            if key2 is not None:
                decryptedKey = mk.decrypt(key2)
                if decryptedKey:
                    return decryptedKey
                    
            decryptedKey = mk.decrypt(key1)
            if decryptedKey:
                return decryptedKey
            
            if key2 is not None:
                decryptedKey = bkmk.decrypt(key2)
                if decryptedKey:
                    return decryptedKey

            decryptedKey = bkmk.decrypt(key1)
            if decryptedKey:
                return decryptedKey
    return None

def decrypt_credential(credential_bytes:bytes, masterkey:MasterKey) -> Any:
    cred = CredentialFile(credential_bytes)
    decrypted = decrypt_blob(cred['Data'], masterkey)
    if decrypted:
        creds = CREDENTIAL_BLOB(decrypted)
        return creds
    return None

def find_masterkey_for_credential_blob(credential_bytes:bytes, masterkeys: Any) -> "Any | None":
    cred = CredentialFile(credential_bytes)
    return find_masterkey_for_blob(cred['Data'], masterkeys=masterkeys)

def decrypt_privatekey(privatekey_bytes:bytes, masterkey:Any, cng: bool = False) -> RSA.RsaKey:
    blob = PVKHeader(privatekey_bytes)
    if blob['SigHeadLen'] > 0:
        blob = PVKFile_SIG(privatekey_bytes)
    else:
        blob = PVKFile(privatekey_bytes)
    key = unhexlify(masterkey.sha1)
    decrypted = decrypt(blob['Blob'], key)
    rsa_temp = PRIVATE_KEY_RSA(decrypted)
    pkcs1 = pvkblob_to_pkcs1(rsa_temp)
    return pkcs1

def find_masterkey_for_privatekey_blob(privatekey_bytes:bytes, masterkeys: List[Any], cng: bool = False) -> "Any | None":
    blob= PVKHeader(privatekey_bytes)
    if len(blob['Remaining']) == 0:
        return None
    if blob['SigHeadLen'] > 0:
        blob=PVKFile_SIG(privatekey_bytes)
    else:
        blob=PVKFile(privatekey_bytes)
    
    masterkey = bin_to_string(blob['Blob']['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def decrypt_vpol(vpol_bytes:bytes, masterkey:Any) -> "VAULT_VPOL_KEYS | None":
    vpol = VAULT_VPOL(vpol_bytes)
    blob = vpol['Blob']

    key = unhexlify(masterkey.sha1)
    decrypted = decrypt(blob, key)
    if decrypted:
        vpol_decrypted = VAULT_VPOL_KEYS(decrypted)
        return vpol_decrypted
    return None
        
def decrypt_vcrd(vcrd_bytes:bytes, vpol_keys:List[bytes]) -> Any:
    blob = VAULT_VCRD(vcrd_bytes)

    for key in vpol_keys:
        key = unhexlify(key)
        cleartext = None
        for i, entry in enumerate(blob.attributesLen):
            try:
                if entry > 28:
                    attribute = blob.attributes[i]
                    if 'IV' in attribute.fields and len(attribute['IV']) == 16:
                        cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
                    else:
                        cipher = AES.new(key, AES.MODE_CBC)
                    cleartext = cipher.decrypt(attribute['Data'])
                    if cleartext is not None:
                        # Lookup schema Friendly Name and print if we find one
                        if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:
                            # Found one. Cast it and print
                            vault = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext)
                            return vault
                        else:
                            # otherwise
                            return cleartext
            except Exception as e:
                if str(e) != '(\'unpack requires a buffer of 4 bytes\', "When unpacking field \'Id2 | <L=0 | b\'\'[:4]\'")':
                    logging.debug(e)
                pass
    return None

def find_masterkey_for_vpol_blob(vault_bytes:bytes, masterkeys: Any) -> "Any | None":
    vault = VAULT_VPOL(vault_bytes)
    blob = vault['Blob']
    masterkey = bin_to_string(blob['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def decrypt_blob(blob_bytes:bytes, masterkey:Any, entropy = None) -> Any:
    blob = DPAPI_BLOB(blob_bytes)
    key = unhexlify(masterkey.sha1)
    decrypted = None
    if entropy is not None:
        decrypted = decrypt(blob, key, entropy=entropy)
    else:
        decrypted = decrypt(blob, key)
    return decrypted

def decrypt(blob, keyHash, entropy = None) -> "bytes | None":
    hash_algo = ALGORITHMS_DATA[blob['HashAlgo']][1]
    block_size = hash_algo.block_size
    for algo in [compute_sessionKey_1, compute_sessionKey_2]:
        sessionKey = algo(keyHash, blob['Salt'], hash_algo, block_size, entropy)
        sessionKey = sessionKey.digest()
        derivedKey = blob.deriveKey(sessionKey)  
        crypto = ALGORITHMS_DATA[blob['CryptAlgo']]
        cipher = crypto[1].new(derivedKey[:crypto[0]], mode=crypto[2], iv=b'\x00'*crypto[3])
        cleartext = cipher.decrypt(blob['Data'])
        try:
            cleartext = unpad(cleartext, crypto[1].block_size)
        except ValueError as e:
            if "Padding is incorrect" in str(e):
                pass
        # Now check the signature
        # ToDo Fix this, it's just ugly, more testing so we can remove one
        toSign = (blob.rawData[20:][:len(blob.rawData)-20-len(blob['Sign'])-4])
        hmac_calculated = algo(keyHash, blob['HMac'], hash_algo, block_size, entropy)
        hmac_calculated.update(toSign)
        if blob['Sign'] == hmac_calculated.digest():
            return cleartext
    return None

def compute_sessionKey_1(key_hash: bytes, salt: bytes, hash_algo: object, block_size: int, entropy: bytes):
    pad_block = key_hash.ljust(block_size, b'\x00')
    ipad = bytearray(i ^ 0x36 for i in pad_block)
    opad = bytearray(i ^ 0x5c for i in pad_block)

    a = hash_algo.new(ipad)
    a.update(salt)

    computed_key = hash_algo.new(opad)
    computed_key.update(a.digest())

    if entropy is not None:
        computed_key.update(entropy)
    return computed_key

def compute_sessionKey_2(key_hash: bytes, salt: bytes, hash_algo: object, block_size: int, entropy: bytes):
    computed_key = HMAC.new(key_hash, salt, hash_algo)
    if entropy is not None:
        computed_key.update(entropy)
    
    return computed_key

def find_masterkey_for_blob(blob_bytes:bytes, masterkeys: Any) -> "Any | None":
    blob = DPAPI_BLOB(blob_bytes)
    masterkey = bin_to_string(blob['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def find_masterkey(masterkey: str, masterkeys: Any) -> "Any | None":
    masterkey = masterkey.lower()
    return next((key for key in masterkeys if key.guid.lower() == masterkey), None)
