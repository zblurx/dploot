import logging
from typing import Any, List
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from binascii import unhexlify

from Cryptodome.Util.Padding import unpad
from Cryptodome.Hash import HMAC

from impacket.uuid import bin_to_string
from impacket.dpapi import MasterKeyFile, MasterKey, CredHist, DomainKey,  DPAPI_BLOB, \
    CREDENTIAL_BLOB, VAULT_VCRD, VAULT_VPOL, VAULT_KNOWN_SCHEMAS, VAULT_VPOL_KEYS, \
    PVK_FILE_HDR, PRIVATE_KEY_BLOB, ALGORITHMS_DATA, privatekeyblob_to_pkcs1, DPAPI_DOMAIN_RSA_MASTER_KEY, CredentialFile

from dploot.lib.crypto import PRIVATE_KEY_RSA, PVKFile, PVKFile_SIG, PVKHeader, deriveKeysFromUser, deriveKeysFromUserkey, pvkblob_to_pkcs1

def decrypt_masterkey(masterkey:bytes, domain_backupkey:bytes= None, dpapi_systemkey:dict()= None, sid: str = '', password:str = None, nthash:str = None) -> Any:
    data = masterkey
    mkf= MasterKeyFile(data)
    dk = mk = ch = bkmk = None
    data = data[len(mkf):]
    if mkf['MasterKeyLen'] > 0:
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        data = data[len(mk):]

    if mkf['BackupKeyLen'] > 0:
        bkmk = MasterKey(data[:mkf['BackupKeyLen']])
        # bkmk.dump()
        data = data[len(bkmk):]

    if mkf['CredHistLen'] > 0:
        ch = CredHist(data[:mkf['CredHistLen']])
        # ch.dump()
        data = data[len(ch):]

    if mkf['DomainKeyLen'] > 0:
        dk = DomainKey(data[:mkf['DomainKeyLen']])
        # dk.dump()
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

    if dpapi_systemkey is not None:
        decryptedKey = mk.decrypt(dpapi_systemkey['UserKey'])
        if decryptedKey:
            return decryptedKey
        decryptedKey = mk.decrypt(dpapi_systemkey['MachineKey'])
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(dpapi_systemkey['UserKey'])
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(dpapi_systemkey['MachineKey'])
        if decryptedKey:
            return decryptedKey

    if dpapi_systemkey is not None and sid != '':
        key1, key2 = deriveKeysFromUserkey(sid, dpapi_systemkey['UserKey'])
        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            return decryptedKey
        key1, key2 = deriveKeysFromUserkey(sid, dpapi_systemkey['MachineKey'])
        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            return decryptedKey

    if nthash is not None and sid != '':
        key1, key2 = deriveKeysFromUserkey(sid, nthash)
        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            return decryptedKey

    if password is not None and sid != '':
        key1, key2, key3 = deriveKeysFromUser(sid, password)

        decryptedKey = mk.decrypt(key3)
        if decryptedKey:
            return decryptedKey

        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            return decryptedKey

        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            return decryptedKey

        decryptedKey = bkmk.decrypt(key3)
        if decryptedKey:
            return decryptedKey

        decryptedKey = bkmk.decrypt(key2)
        if decryptedKey:
            return decryptedKey

        decryptedKey = bkmk.decrypt(key1)
        if decryptedKey:
            return decryptedKey
            
    return None

def decrypt_credential(credential_bytes:bytes, masterkey:MasterKey) -> Any:
    cred = CredentialFile(credential_bytes)
    decrypted = decrypt_blob(cred['Data'],masterkey=masterkey)
    if decrypted is not None:
        creds = CREDENTIAL_BLOB(decrypted)
        return creds
    return None

def find_masterkey_for_credential_blob(credential_bytes:bytes, masterkeys: Any) -> Any | None:
    cred = CredentialFile(credential_bytes)
    return find_masterkey_for_blob(cred['Data'], masterkeys=masterkeys)

def decrypt_privatekey(privatekey_bytes:bytes, masterkey:Any, cng: bool = False) -> RSA.RsaKey:
    blob= PVKHeader(privatekey_bytes)
    if blob['SigHeadLen'] > 0:
        blob=PVKFile_SIG(privatekey_bytes)
    else:
        blob=PVKFile(privatekey_bytes)
    key = unhexlify(masterkey.sha1)
    decrypted = decrypt(blob['Blob'], key)
    rsa_temp = PRIVATE_KEY_RSA(decrypted)
    pkcs1 = pvkblob_to_pkcs1(rsa_temp)
    return pkcs1

def find_masterkey_for_privatekey_blob(privatekey_bytes:bytes, masterkeys: List[Any], cng: bool = False) -> Any | None:
    blob= PVKHeader(privatekey_bytes)
    if len(blob['Remaining']) == 0:
        return None
    if blob['SigHeadLen'] > 0:
        blob=PVKFile_SIG(privatekey_bytes)
    else:
        blob=PVKFile(privatekey_bytes)
    
    masterkey = bin_to_string(blob['Blob']['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def decrypt_vpol(vpol_bytes:bytes, masterkey:Any) -> (VAULT_VPOL_KEYS | None):
    vpol = VAULT_VPOL(vpol_bytes)
    blob = vpol['Blob']

    key = unhexlify(masterkey.sha1)
    decrypted = decrypt(blob, key)
    if decrypted is not None:
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

def find_masterkey_for_vpol_blob(vault_bytes:bytes, masterkeys: Any) -> Any | None:
    vault = VAULT_VPOL(vault_bytes)
    blob = vault['Blob']
    masterkey = bin_to_string(blob['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def decrypt_blob(blob_bytes:bytes, masterkey:Any, entropy = None) -> Any:
    blob = DPAPI_BLOB(blob_bytes)
    key = unhexlify(masterkey.sha1)
    decrypted = None
    if entropy is not None:
        decrypted = blob.decrypt(blob, key, entropy=entropy)
    else:
        decrypted = decrypt(blob, key)
    return decrypted

def decrypt(blob, keyHash, entropy = None) -> (bytes | None):
    sessionKey = HMAC.new(keyHash, blob['Salt'], ALGORITHMS_DATA[blob['HashAlgo']][1])
    if entropy is not None:
        sessionKey.update(entropy)

    sessionKey = sessionKey.digest()

    # Derive the key
    derivedKey = blob.deriveKey(sessionKey)

    cipher = ALGORITHMS_DATA[blob['CryptAlgo']][1].new(derivedKey[:ALGORITHMS_DATA[blob['CryptAlgo']][0]],
                            mode=ALGORITHMS_DATA[blob['CryptAlgo']][2], iv=b'\x00'*ALGORITHMS_DATA[blob['CryptAlgo']][3])
    cleartext = unpad(cipher.decrypt(blob['Data']), ALGORITHMS_DATA[blob['CryptAlgo']][1].block_size)

    # Now check the signature

    # ToDo Fix this, it's just ugly, more testing so we can remove one
    toSign = (blob.rawData[20:][:len(blob.rawData)-20-len(blob['Sign'])-4])

    # Calculate the different HMACKeys
    keyHash2 = keyHash + b"\x00"*ALGORITHMS_DATA[blob['HashAlgo']][1].block_size
    ipad = bytearray([i ^ 0x36 for i in bytearray(keyHash2)][:ALGORITHMS_DATA[blob['HashAlgo']][1].block_size])
    opad = bytearray([i ^ 0x5c for i in bytearray(keyHash2)][:ALGORITHMS_DATA[blob['HashAlgo']][1].block_size])
    a = ALGORITHMS_DATA[blob['HashAlgo']][1].new(ipad)
    a.update(blob['HMac'])

    hmacCalculated1 = ALGORITHMS_DATA[blob['HashAlgo']][1].new(opad)
    hmacCalculated1.update(a.digest())

    if entropy is not None:
        hmacCalculated1.update(entropy)

    hmacCalculated1.update(toSign)

    hmacCalculated3 = HMAC.new(keyHash, blob['HMac'], ALGORITHMS_DATA[blob['HashAlgo']][1])
    if entropy is not None:
        hmacCalculated3.update(entropy)

    hmacCalculated3.update(toSign)

    if hmacCalculated1.digest() == blob['Sign'] or hmacCalculated3.digest() == blob['Sign']:
        return cleartext
    else:
        return None

def find_masterkey_for_blob(blob_bytes:bytes, masterkeys: Any) -> Any | None:
    blob = DPAPI_BLOB(blob_bytes)
    masterkey = bin_to_string(blob['GuidMasterKey'])
    return find_masterkey(masterkey=masterkey, masterkeys=masterkeys)

def find_masterkey(masterkey:  str, masterkeys: Any) -> Any | None:
    for mk in masterkeys:
        if masterkey.lower() == mk.guid.lower():
            return mk
    return None