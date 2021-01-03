import os
import stat
import sys
import orjson
from typing import Union
from orjson import JSONEncodeError

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from certsGenerator.helpers import checkConf

from certsGenerator.globals_conf import curveMapping
from certsGenerator.globals_conf import serialization_mapping


def loadConf(fileName: str, format: str = "json") -> dict:
    generalConf = {}
    try:
        with open(fileName, mode="r", encoding="utf-8") as file:
            try:
                generalConf = orjson.loads(file.read())
                checkConf(generalConf)
            except JSONEncodeError as e:
                sys.exit(f"enable to load string from {fileName}: {e}")
    except OSError as e:
        print("please make sure to execute the script like this: \"python src/main.py\"")
        sys.exit(f"failed to open {fileName}: {e}")
    return generalConf


def loadFile(fileName: str) -> bytes:
    content = b""
    try:
        with open(fileName, mode="rb") as f:
            content = f.read()
    except OSError as e:
        sys.exit(f"failed to open {fileName}: {e}")
    return content


def storePrivateKey(
    certConf: dict,
    private_key: Union[
        ec.EllipticCurvePrivateKeyWithSerialization, ec.EllipticCurvePrivateKey
    ],
    path: str,
) -> None:
    # get passphrase
    passphrase = getPassphrase(certConf=certConf)
    encryption_algorithm: serialization.KeySerializationEncryption
    if passphrase:
        encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption_algorithm = serialization.NoEncryption()  # type: ignore

    # get other params from conf
    encoding = certConf["private_key"]["encoding"]
    key_format = certConf["private_key"]["format"]
    try:
        with open(path, mode="wb") as f:
            encoding = serialization_mapping[encoding]
            fmt = serialization_mapping[key_format]
            f.write(
                # mypy type issue here
                # in vscode private_key has no private_bytes method
                # but python console shows one
                private_key.private_bytes(  # type: ignore
                    encoding=encoding,
                    format=fmt,  # type: ignore
                    encryption_algorithm=encryption_algorithm,
                )
            )
        try:
            os.chmod(path, mode=0o600)
        except OSError as e:
            sys.exit(f"can't set permission {stat.S_IRUSR} on {path}: {e}")
    except OSError as e:
        sys.exit(f"failed to write file {path}: {e}")


def storePublicKey(path: str, cert: x509.Certificate) -> None:
    try:
        with open(path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    except OSError:
        sys.exit(f"can't save public key in {path}")


def getPrivateKey(certConf: dict, extensions: dict) -> ec.EllipticCurvePrivateKey:
    if "storage" not in certConf.keys():
        raise ValueError(f"key not found in {certConf}")
        sys.exit()
    path = certConf["storage"]["path"]
    fileName = certConf["storage"]["fileName"]
    certName = certConf["subject_name"]

    curve_conf = certConf["private_key"]["algorithm"]["params"]["curve"]

    keyExt = extensions["key"]
    keyFile = f"{path}/{fileName}.{keyExt}"
    private_key = None
    if not os.path.exists(path):
        os.makedirs(path)
    elif os.path.exists(keyFile):
        private_key_bytes = loadFile(fileName=keyFile)
        password = getPassphrase(certConf)
        if password:
            private_key = serialization.load_pem_private_key(
                private_key_bytes, password=password
            )  # type: ignore
        else:
            private_key = serialization.load_pem_private_key(
                private_key_bytes
            )  # type: ignore
    else:
        private_key = ec.generate_private_key(
            curve=curveMapping[curve_conf]
        )  # type: ignore
        storePrivateKey(certConf=certConf, private_key=private_key, path=keyFile)
    return private_key  # type: ignore


def getPassphrase(certConf: dict) -> bytes:
    # get passphrase
    p = certConf["private_key"]["passphrase"]["path"]
    n = certConf["private_key"]["passphrase"]["fileName"]
    passFile = f"{p}/{n}"
    passphrase = loadFile(passFile)

    if not type(passphrase) == bytes:
        raise ValueError("passphrase should be of bytes type")
        sys.exit()
    return passphrase


def getFileExtensions(generalConf: dict) -> dict:
    keyExt = generalConf["defaults"]["file_extentions"]["private_key"]
    csrExt = generalConf["defaults"]["file_extentions"]["certificate_signing_request"]
    crtExt = generalConf["defaults"]["file_extentions"]["signed_certificate"]

    ext = {"key": keyExt, "csr": csrExt, "crt": crtExt}
    return ext


def getCertConf(generalConf: dict, certName: str) -> dict:
    certs = generalConf["certs"]
    conf = {}
    for cert in certs:
        if cert["name"] == certName:
            conf = cert
            break
    return conf["conf"]
