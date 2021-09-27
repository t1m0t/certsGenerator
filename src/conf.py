import datetime
import sys
import logging

from orjson import loads, JSONEncodeError
from typing import Union

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding

from src.helpers import loadFile


class Conf:
    def __init__(self, confFile: str):
        self.general = self._load(confFile)
        self.fileExtenstions = self._getFileExt()
        self.checkRegistry = list()

        # run checks
        self._checkCertName()
        self._checkEncoding()
        self._checkExtendedKeyUsage()
        self._checkKeyUsage()
        self._checkNotValidDate()
        self._checkPubKeyEncodingPresent()
        self._checkRedundantNames()
        self._checkSerialization()

    def getCert(self, certName: str) -> dict:
        certs = self.general["certs"]
        conf = {}
        for cert in certs:
            if cert["name"] == certName:
                conf = cert
                break
        if not (len(conf) > 0):
            logging.error(f"cert {certName} not found")
            raise ValueError()
            sys.exit()
        return conf.get("conf")

    def get(self, certName: str, field: str, isExt: bool = True) -> dict:
        certConf = self.getCert(certName)
        if isExt is True:
            return certConf.get("extensions").get(field)
        elif certConf.get(field):
            return certConf.get(field)
        else:
            logging.error(f"{field} not found in conf")
            raise ValueError()
            sys.exit()

    def getCertPath(self, certName: str, ext: str) -> str:
        certConf = self.getCert(certName)
        path = certConf.get("storage").get("path")
        fileName = certConf.get("storage").get("fileName")
        ext = self.fileExtenstions.get(ext)
        certpath = f"{path}/{fileName}.{ext}"
        return certpath

    def getPath(self, certName: str) -> str:
        certConf = self.getCert(certName)
        path = certConf.get("storage").get("path")
        return path

    def getPassphrase(self, certName: str) -> Union[bytes, None]:
        # get passphrase
        certConf = self.getCert(certName)
        if certConf.get("private_key") and certConf.get("private_key").get(
            "passphrase"
        ):
            p = certConf.get("private_key").get("passphrase").get("path")
            n = certConf.get("private_key").get("passphrase").get("fileName")
            passFile = f"{p}/{n}"
            passphrase = loadFile(passFile)

            if not type(passphrase) == bytes:
                logging.error("passphrase should be of bytes type")
                raise ValueError()
                sys.exit()
            return passphrase
        else:
            passphrase = None
            return passphrase

    def _load(self, fileName: str) -> dict:
        generalConf = {}
        try:
            with open(fileName, mode="r", encoding="utf-8") as file:
                try:
                    generalConf = loads(file.read())
                except JSONEncodeError as e:
                    sys.exit(f"enable to load string from {fileName}: {e}")
        except OSError as e:
            logging.error(f"failed to open {fileName}: {e}")
        return generalConf

    def _getFileExt(self) -> dict:
        return self.general.get("defaults").get("file_extentions")

    def _checkPubKeyEncodingPresent(self) -> None:
        # check if the public key encoding is persent
        certs = self.general["certs"]
        for cert in certs:
            try:
                cert.get("conf").get("public_key").get("encoding")
            except KeyError as e:
                certName = cert.get("name")
                logging.error(
                    f"Configuration file error: can't find public key encoding for {certName}, {e}"
                )
                raise ValueError()
                sys.exit()

    def _checkRedundantNames(self) -> None:
        # check if no redundant certs names
        certs = self.general.get("certs")
        names: dict = {}
        for cert in certs:
            if cert["name"] in names.keys():
                names[cert["name"]] += 1
            else:
                names[cert["name"]] = 1
        for k, v in names.items():
            if v > 1:
                logging.error(f"Configuration file error: {k} appears {v} times")
                raise ValueError()
                sys.exit()

    def _checkNotValidDate(self) -> None:
        # check not_valid_before not_valid_after
        certs = self.general.get("certs")
        for certConf in certs:
            certConf = certConf.get("conf")
            if certConf.get("not_valid_before") == "now":
                nvb = datetime.datetime.utcnow()
            elif isinstance(int(), certConf.get("not_valid_before")) or isinstance(
                int, certConf.get("not_valid_after")
            ):
                nvb = datetime.datetime.utcnow() + datetime.timedelta(
                    days=certConf.get("not_valid_before")
                )
            else:
                logging.error(f'invalid value from {nvb}, should be of int or "now"')
                raise ValueError()
                sys.exit()

    def _checkCertName(self) -> None:
        certs = self.general.get("certs")
        for cert in certs:
            subjectName = cert.get("conf").get("subject_name")
            certName = cert.get("name")
            if certName != subjectName:
                logging.error(
                    f"certname {certName} has to be the same than the subject name, found {subjectName}"
                )
                raise ValueError()
                sys.exit()

    def _checkKeyUsage(self) -> None:
        certs = self.general.get("certs")
        for cert in certs:
            certName = cert.get("name")
            for ku in (
                cert.get("conf").get("extensions").get("KeyUsage").get("items")
            ):
                if ku.lower() not in self.keyUsage:
                    logging.error(
                        f"{ku} not found in allowed keyUsage for {certName}"
                    )
                    raise ValueError()
                    sys.exit()

    def _checkExtendedKeyUsage(self) -> None:
        certs = self.general.get("certs")
        for cert in certs:
            if cert.get("conf").get("extensions").get("ExtendedKeyUsage"):
                for ku in (
                    cert.get("conf")
                    .get("extensions")
                    .get("ExtendedKeyUsage")
                    .get("items")
                ):
                    if ku.upper() not in self.extendedKeyUsageMapping.keys():
                        logging.error(f"{ku} not found in allowed ExtendedKeyUsage")
                        raise ValueError()
                        sys.exit()

    def _checkEncoding(self) -> None:
        certs = self.general.get("certs")
        for cert in certs:
            certName = cert.get("name")
            enc_priv = cert.get("conf").get("private_key").get("encoding")
            enc_pub = cert.get("conf").get("public_key").get("encoding")
            if (enc_priv not in self.encodingMapping.keys()) or (
                enc_pub not in self.encodingMapping.keys()
            ):
                logging.error(
                    f"encoding not found for {certName} in allowed encoding formats"
                )
                raise ValueError()
                sys.exit()

    def _checkSerialization(self) -> None:
        certs = self.general.get("certs")
        for cert in certs:
            certName = cert.get("name")
            serialization = cert.get("conf").get("private_key").get("serialization")
            if serialization not in self.privateSerializationMapping.keys():
                logging.error(
                    f"serialization not found for private key of {certName} in allowed serialization formats"
                )
                raise ValueError()
                sys.exit()

    nameAttributesMapping = {
        "COUNTRY_NAME": NameOID.COUNTRY_NAME,
        "STATE_OR_PROVINCE_NAME": NameOID.STATE_OR_PROVINCE_NAME,
        "LOCALITY_NAME": NameOID.LOCALITY_NAME,
        "ORGANIZATION_NAME": NameOID.ORGANIZATION_NAME,
        "COMMON_NAME": NameOID.COMMON_NAME,
    }

    extensionMapping = {
        "SubjectAlternativeName": x509.SubjectAlternativeName,
        "KeyUsage": x509.KeyUsage,
        "BasicConstraints": x509.BasicConstraints,
        "NameConstraints": x509.NameConstraints,
        "NameAttribute": x509.NameAttribute,
        "AuthorityKeyIdentifier": x509.AuthorityKeyIdentifier,
        "DNSName": x509.DNSName,
        "IPAddress": x509.IPAddress,
    }

    curveMapping = {
        "SECP256R1": ec.SECP256R1(),
        "SECP384R1": ec.SECP384R1(),
        "SECP521R1": ec.SECP521R1(),
    }

    encodingMapping = {
        "PEM": serialization.Encoding.PEM,
        "DER": serialization.Encoding.DER,
        "Raw": serialization.Encoding.Raw,
        "OpenSSH": serialization.Encoding.OpenSSH,
    }

    privateSerializationMapping = {
        "PKCS8": serialization.PrivateFormat.PKCS8,
        "TraditionalOpenSSL": serialization.PrivateFormat.TraditionalOpenSSL,
        "Raw": serialization.PrivateFormat.Raw,
        "OpenSSH": serialization.PrivateFormat.OpenSSH,
    }

    publicSerializationMapping = {
        "SubjectPublicKeyInfo": serialization.PublicFormat.SubjectPublicKeyInfo,
        "PKCS1": serialization.PublicFormat.PKCS1,
        "Raw": serialization.PublicFormat.Raw,
        "OpenSSH": serialization.PublicFormat.OpenSSH,
    }

    RSApaddingMapping = {
        "PSS": padding.PSS,
        "OAEP": padding.OAEP,
        "PKCS1v15": padding.PKCS1v15,
    }

    hashMapping = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }

    keyUsage = [
        "digital_signature",
        "content_commitment",
        "key_encipherment",
        "data_encipherment",
        "key_agreement",
        "key_cert_sign",
        "crl_sign",
        "encipher_only",
        "decipher_only",
    ]

    extendedKeyUsageMapping = {
        "SERVER_AUTH": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        "CLIENT_AUTH": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        "CODE_SIGNING": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        "EMAIL_PROTECTION": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "TIME_STAMPING": x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
        "OCSP_SIGNING": x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
        "ANY_EXTENDED_KEY_USAGE": x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    }
