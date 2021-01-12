import os
import stat
import sys
import orjson
from typing import Union
from orjson import JSONEncodeError

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from certsGenerator.conf import Conf
from certsGenerator.helpers import loadFile
from certsGenerator.certBuilder import CertBuilder


class CertManager:
    def __init__(self, confFile: str):
        self.conf: Conf = Conf(confFile=confFile)

    def storePrivateKey(
        self,
        certName: str,
        private_key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
    ) -> None:
        certConf = self.conf.getCert(certName=certName)
        # get passphrase
        passphrase = self.conf.getPassphrase(certName=certName)
        encryption_algorithm: serialization.KeySerializationEncryption
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()

        # get other params from conf
        path = self.conf.getCertPath(certName=certName, ext="private_key")
        encoding = certConf["private_key"]["encoding"]
        key_format = certConf["private_key"]["format"]
        try:
            with open(path, mode="wb") as f:
                encoding = self.conf.serializationMapping[encoding]
                fmt = self.conf.serializationMapping[key_format]
                f.write(
                    private_key.private_bytes(  # type: ignore
                        encoding=encoding,
                        format=fmt,
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

    def getPrivateKey(
        self, certName: str
    ) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
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
            print(f"========== Private key of {certName} file already exist")
            private_key_bytes = loadFile(fileName=keyFile)
            password = self.conf.getPassphrase(certName=certName)
            try:
                private_key = serialization.load_pem_private_key(  # type: ignore
                    private_key_bytes, password=password
                )
            except ValueError as e:
                print(
                    f"Error while loading the key {keyFile}. Please make sure the key is properly generated and the file is not empty."
                )
                sys.exit()
        else:
            print(f"========== Creating private key of {certName}")
            key_type = certConf["private_key"]["algorithm"]["type"]
            params = certConf["private_key"]["algorithm"]["params"]
            if key_type == "EC":
                private_key = ec.generate_private_key(  # type: ignore
                    curve=self.conf.curveMapping[params["curve"]]
                )
            elif key_type == "RSA":
                private_key = rsa.generate_private_key(  # type: ignore
                    public_exponent=65537, key_size=int(params["key_size"])
                )
            self.storePrivateKey(certName=certName, private_key=private_key)  # type: ignore
        return private_key  # type: ignore

    def createCerts(self, certName: str) -> None:
        certConf = self.conf.getCert(certName=certName)
        # get the private key (created if it doesn't exist yet)
        private_key = self.getPrivateKey(certName=certName)

        # regarding cert
        certFile = self.conf.getCertPath(certName=certName, ext="signed_certificate")
        issuer_name = certConf["issuer_name"]
        # check if cert exists, otherwise create it
        if not os.path.exists(certFile):
            print("========== Create cert file")
            # but to create the cert, we need issuer key to sign it
            issuer_private_key = self.getPrivateKey(certName=issuer_name)
            # ok then we build the cert
            subject_name = certConf["subject_name"]
            ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
            cert = CertBuilder(certName=subject_name, conf=self.conf, ski=ski).builder
            cert = cert.public_key(private_key.public_key())
            # now sign the cert with the issuer private key
            hashAlg = self.conf.hashMapping[certConf["private_key"]["sign_with_alg"]]
            cert = cert.sign(private_key=issuer_private_key, algorithm=hashAlg)  # type: ignore
            # now store the cert
            self.storePublicKey(certName=certName, cert=cert)  # type: ignore
            print(
                f"========== certs created for {certName} with crt signed by {issuer_name}"
            )
        else:
            print("========== Cert file already exists")

        self._checkSignature(subjectName=certName, issuerName=issuer_name)

    def _checkSignature(self, subjectName: str, issuerName: str) -> None:
        # conf
        print(f"========== checking signature of {subjectName}")
        issuerCrtFile = self.conf.getCertPath(
            certName=issuerName, ext="signed_certificate"
        )
        subjectCrtFile = self.conf.getCertPath(
            certName=subjectName, ext="signed_certificate"
        )
        # load data
        pem_issuer_public_key = loadFile(fileName=issuerCrtFile)
        pem_subject_public_key = loadFile(fileName=subjectCrtFile)
        # check
        issuer_public_key = x509.load_pem_x509_certificate(  # type: ignore
            pem_issuer_public_key
        ).public_key()
        cert_to_check = x509.load_pem_x509_certificate(pem_subject_public_key)  # type: ignore
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                self.conf.RSApaddingMapping["PKCS1v15"](),
                cert_to_check.signature_hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(  # type: ignore
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
                ec.ECDSA(cert_to_check.signature_hash_algorithm),  # type: ignore
            )
        else:
            raise ValueError(
                f"Failed to verify due to unsupported algorythm {type(cert_to_check.public_key())}"
            )
            sys.exit()

        print("========== signature OK")
