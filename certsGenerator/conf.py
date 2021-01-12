import datetime
import sys

from orjson import loads, JSONEncodeError
from typing import Callable, Union

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import padding

from certsGenerator.helpers import loadFile

checkRegistry = []


class MetaRegistry(type):
    @classmethod
    def __prepare__(mcl, name, bases):  # type: ignore
        def register_check(r) -> Callable:  # type: ignore
            def deco(f: Callable) -> Callable:
                checkRegistry.append(f)
                return f

            return deco

        d = dict()
        d["register_check"] = register_check
        return d

    def __new__(mcl, name, bases, dct):  # type: ignore
        del dct["register_check"]
        cls = super().__new__(mcl, name, bases, dct)
        return cls


class Conf(object, metaclass=MetaRegistry):
    def __init__(self, confFile: str):
        self.general = self._load(confFile)
        self._checkConf()
        self.fileExtenstions = self._getFileExt()

    def getCert(self, certName: str) -> dict:
        certs = self.general["certs"]
        conf = {}
        for cert in certs:
            if cert["name"] == certName:
                conf = cert
                break
        if not (len(conf) > 0):
            raise ValueError(f'cert name "{certName}" not found')
        return conf["conf"]

    def get(self, certName: str, field: str, isExt: bool = True) -> dict:
        certConf = self.getCert(certName)
        if isExt is True:
            return certConf["extensions"][field]
        elif certConf[field]:
            return certConf[field]
        else:
            raise ValueError(f"{field} not found in conf")
            sys.exit()

    def getCertPath(self, certName: str, ext: str) -> str:
        certConf = self.getCert(certName)
        path = certConf["storage"]["path"]
        fileName = certConf["storage"]["fileName"]
        ext = self.fileExtenstions[ext]
        certpath = f"{path}/{fileName}.{ext}"
        return certpath

    def getPath(self, certName: str) -> str:
        certConf = self.getCert(certName)
        path = certConf["storage"]["path"]
        return path

    def getPassphrase(self, certName: str) -> Union[bytes, None]:
        # get passphrase
        certConf = self.getCert(certName)
        if certConf.get("private_key") and certConf.get("private_key").get("passphrase"):  # type: ignore
            p = certConf["private_key"]["passphrase"]["path"]
            n = certConf["private_key"]["passphrase"]["fileName"]
            passFile = f"{p}/{n}"
            passphrase = loadFile(passFile)

            if not type(passphrase) == bytes:
                raise ValueError("passphrase should be of bytes type")
                sys.exit()
            return passphrase
        else:
            passphrase = None  # type: ignore
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
            print(
                'please make sure to execute the script like this: "python src/main.py"'
            )
            sys.exit(f"failed to open {fileName}: {e}")
        return generalConf

    def _getFileExt(self) -> dict:
        return self.general["defaults"]["file_extentions"]

    def _checkConf(self) -> None:
        for fun in checkRegistry:
            fun()

    @register_check  # type: ignore
    def _checkRedundantNames(self) -> None:
        # check if no redundant certs names
        certs = self.general["certs"]
        names: dict = {}
        for cert in certs:
            if cert["name"] in names.keys():
                names[cert["name"]] += 1
            else:
                names[cert["name"]] = 1
        for k, v in names.items():
            if v > 1:
                raise ValueError(f"Configuration file error: {k} appears {v} times")
                sys.exit()

    @register_check  # type: ignore
    def _checkNotValidDate(self) -> None:
        # check not_valid_before not_valid_after
        certs = self.general["certs"]
        for certConf in certs:
            certConf = certConf["conf"]
            if certConf["not_valid_before"] == "now":
                nvb = datetime.datetime.utcnow()
            elif isinstance(int(), certConf["not_valid_before"]) or isinstance(
                int, certConf["not_valid_after"]
            ):
                nvb = datetime.datetime.utcnow() + datetime.timedelta(
                    days=certConf["not_valid_before"]
                )
            else:
                raise ValueError(f'invalid value from {nvb}, should be of int or "now"')
                sys.exit()

    @register_check  # type: ignore
    def _checkCertName(self) -> None:
        certs = self.general["certs"]
        for cert in certs:
            subjectName = cert["conf"]["subject_name"]
            certName = cert["name"]
            if certName != subjectName:
                raise ValueError(
                    f"certname {certName} has to be the same than the subject name, found {subjectName}"
                )
                sys.exit()

    @register_check  # type: ignore
    def _checkKeyUsage(self) -> None:
        certs = self.general["certs"]
        for cert in certs:
            for ku in cert["extensions"]["KeyUsage"]["items"]:
                if ku.upper not in self.keyUsage:
                    raise ValueError(f"{ku} not found in allowed keyUsage")
                sys.exit()

    @register_check  # type: ignore
    def _checkExtendedKeyUsage(self) -> None:
        certs = self.general["certs"]
        for cert in certs:
            for ku in cert["extensions"]["ExtendedKeyUsage"]["items"]:
                if ku.upper() not in self.extendedKeyUsageMapping.keys():
                    raise ValueError(f"{ku} not found in allowed ExtendedKeyUsage")
                sys.exit()

    nameAttributesMapping = {
        "COUNTRY_NAME": NameOID.COUNTRY_NAME,
        "STATE_OR_PROVINCE_NAME": NameOID.STATE_OR_PROVINCE_NAME,
        "LOCALITY_NAME": NameOID.LOCALITY_NAME,
        "ORGANIZATION_NAME": NameOID.ORGANIZATION_NAME,
        "COMMON_NAME": NameOID.COMMON_NAME,
    }

    extentionMapping = {
        "SubjectAlternativeName": x509.SubjectAlternativeName,
        "KeyUsage": x509.KeyUsage,
        "BasicConstraints": x509.BasicConstraints,
        "NameConstraints": x509.NameConstraints,
        "NameAttribute": x509.NameAttribute,
        "AuthorityKeyIdentifier": x509.AuthorityKeyIdentifier,
        "DNSName": x509.DNSName,
        "IPAddress": x509.IPAddress,
    }

    # one supported for the moment
    curveMapping = {"SECP521R1": ec.SECP521R1()}

    serializationMapping = {
        "PEM": serialization.Encoding.PEM,
        "PKCS8": serialization.PrivateFormat.PKCS8,
        "TraditionalOpenSSL": serialization.PrivateFormat.TraditionalOpenSSL,
        "Raw": serialization.PrivateFormat.Raw,
        "OpenSSH": serialization.PrivateFormat.OpenSSH,  # type: ignore
    }

    RSApaddingMapping = {
        "PSS": padding.PSS,
        "OAEP": padding.OAEP,
        "PKCS1v15": padding.PKCS1v15,
    }

    hashMapping = {"sha512": hashes.SHA512(), "sha256": hashes.SHA256()}

    keyUsage = set(
        [
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
    )

    extendedKeyUsageMapping = {
        "SERVER_AUTH": x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
        "CLIENT_AUTH": x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
        "CODE_SIGNING": x509.oid.ExtendedKeyUsageOID.CODE_SIGNING,
        "EMAIL_PROTECTION": x509.oid.ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "TIME_STAMPING": x509.oid.ExtendedKeyUsageOID.TIME_STAMPING,
        "OCSP_SIGNING": x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING,
        "ANY_EXTENDED_KEY_USAGE": x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
    }
