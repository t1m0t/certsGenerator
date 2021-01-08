import os
import stat
import sys
import orjson
from typing import Union
from orjson import JSONEncodeError

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from certsGenerator.conf import Conf
from certsGenerator.helpers import loadFile
from certsGenerator.certBuilder import CertBuilder


class CertManager():
    def __init__(self, confFile: str):
        self.conf: Conf = Conf(confFile=confFile)

    def storePrivateKey(self, certName: str, private_key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]) -> None:
        certConf = self.conf.getCert(certName=certName)
        # get passphrase
        passphrase = self.conf.getPassphrase(certName=certName)
        encryption_algorithm: serialization.KeySerializationEncryption
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()  # type: ignore

        # get other params from conf
        path = self.conf.getCertPath(certName=certName, ext="private_key")
        encoding = certConf["private_key"]["encoding"]
        key_format = certConf["private_key"]["format"]
        try:
            with open(path, mode="wb") as f:
                encoding = self.conf.serialization_mapping[encoding]
                fmt = self.conf.serialization_mapping[key_format]
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

    def storePublicKey(self, certName: str, cert: x509.Certificate) -> None:
        path = self.conf.getCertPath(certName=certName, ext="signed_certificate")
        try:
            with open(path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        except OSError:
            sys.exit(f"can't save public key in {path}")

    def getPrivateKey(self, certName: str) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
        certConf = self.conf.getCert(certName=certName)
        if "storage" not in certConf.keys():
            raise ValueError(f"key not found in {certConf}")
            sys.exit()
        path = certConf["storage"]["path"]
        fileName = certConf["storage"]["fileName"]
        certName = certConf["subject_name"]

        keyFile = self.conf.getCertPath(certName=certName, ext="private_key")

        private_key = None
        if not os.path.exists(path):
            os.makedirs(path)

        if os.path.exists(keyFile):
            private_key_bytes = loadFile(fileName=keyFile)
            password = self.conf.getPassphrase(certName=certName)
            if password:
                private_key = serialization.load_pem_private_key(
                    private_key_bytes, password=password
                )  # type: ignore
            else:
                private_key = serialization.load_pem_private_key(
                    private_key_bytes, password=password
                )  # type: ignore
        else:
            if certConf["private_key"]["algorithm"]["type"] == "EC":
                curve_conf = certConf["private_key"]["algorithm"]["params"]["curve"]
                private_key = ec.generate_private_key(
                    curve=self.conf.curveMapping[curve_conf]
                )  # type: ignore
            elif certConf["private_key"]["algorithm"]["type"] == "RSA":
                rsa_params = certConf["private_key"]["algorithm"]["params"]
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=rsa_params["key_size"]
                )
            self.storePrivateKey(certName=certName, private_key=private_key)
        return private_key  # type: ignore

    def createCerts(self, certName: str) -> None:
        certConf = self.conf.getCert(certName=certName)
        # get the private key (created if it doesn't exist yet)
        private_key = self.getPrivateKey(certName=certName)

        # regarding cert
        path = certConf["storage"]["path"]
        fileName = certConf["storage"]["fileName"]
        crtExt = self.conf.fileExtenstions["signed_certificate"]
        certFile = f"{path}/{fileName}.{crtExt}"
        # check if cert exists
        if not os.path.exists(certFile):
            # but to create the cert, we need issuer key
            issuer_name = certConf["issuer_name"]
            issuer_private_key = self.getPrivateKey(certName=issuer_name)
            # ok then we build the cert
            subject_name = certConf["subject_name"]
            cert = CertBuilder(certName=subject_name, conf=self.conf, private_key=private_key).certificate

            self.storePublicKey(certName=certName, cert=cert)

            print(f"cert created in {certFile}")
