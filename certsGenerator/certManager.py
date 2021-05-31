import logging
import os
import stat
import sys
from typing import Tuple, Union, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519

from certsGenerator.conf import Conf
from certsGenerator.helpers import loadFile
from certsGenerator.certBuilder import CertBuilder


class CertManager:
    def __init__(self, confFile: str):
        self.conf: Conf = Conf(confFile=confFile)

    def storePrivateKey(
        self,
        certName: str,
        private_key: Union[
            ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey
        ],
    ) -> None:
        certConf = self.conf.getCert(certName=certName)

        # get passphrase
        passphrase = self.conf.getPassphrase(certName=certName)

        # set encryption algorithm
        encryption_algorithm = self._getEncryptionAlgorithm(passphrase=passphrase)

        # get other params from conf
        encoding, key_format = self._getParamsForPrivateBytes(certConf=certConf)

        # get path and save the key file
        path = self.conf.getCertPath(certName=certName, ext="private_key")
        try:
            with open(path, mode="wb") as f:
                f.write(
                    private_key.private_bytes(  # type: ignore
                        encoding=encoding,
                        format=key_format,
                        encryption_algorithm=encryption_algorithm,
                    )
                )
            try:
                os.chmod(path, mode=0o600)
            except OSError as e:
                logging.error(f"can't set permission {stat.S_IRUSR} on {path}: {e}")
        except OSError as e:
            logging.error(f"failed to write file {path}: {e}")

    def storePublicKey(self, certName: str, cert: x509.Certificate) -> None:
        path = self.conf.getCertPath(certName=certName, ext="signed_certificate")
        certConf = self.conf.getCert(certName=certName)
        try:
            enc = certConf.get("public_key").get("encoding")
            content = ""
            if enc == "PEM":
                content = cert.public_bytes(serialization.Encoding.PEM)
            elif enc == "DER":
                content = cert.public_bytes(serialization.Encoding.DER)
            with open(path, "wb") as f:
                f.write(content)

        except OSError:
            logging.error(f"can't save public key in {path}")

    def getPrivateKey(
        self, certName: str
    ) -> Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey]:
        certConf = self.conf.getCert(certName=certName)
        if "storage" not in certConf.keys():
            raise ValueError(f"key not found in {certConf}")
            sys.exit()
        path = certConf["storage"]["path"]
        certName = certConf["subject_name"]

        keyFile = self.conf.getCertPath(certName=certName, ext="private_key")

        private_key = None
        if not os.path.exists(path):
            os.makedirs(path)

        if os.path.exists(keyFile):
            logging.info(f"Private key of {certName} file already exist")
            private_key_bytes = loadFile(fileName=keyFile)
            password = self.conf.getPassphrase(certName=certName)
            try:
                if certConf.get("private_key").get("encoding") == "PEM":
                    private_key = serialization.load_pem_private_key(  # type: ignore
                        private_key_bytes, password=password
                    )
                elif certConf.get("private_key").get("encoding") == "DER":
                    private_key = serialization.load_der_private_key(  # type: ignore
                        private_key_bytes, password=password
                    )
            except ValueError as e:
                logging.error(
                    f"Error while loading the private key {keyFile}. Please make sure the key is properly generated and the file is not empty."
                )

        else:
            logging.info(f"Creating private key of {certName}")
            key_type: str = certConf["private_key"]["algorithm"]["type"].upper()
            params = []

            if certConf.get("private_key").get("algorithm").get("params"):
                params = certConf["private_key"]["algorithm"]["params"]
            else:
                params = None

            if key_type == "EC":
                private_key = ec.generate_private_key(  # type: ignore
                    curve=self.conf.curveMapping[params["curve"]]
                )
            elif key_type == "RSA":
                private_key = rsa.generate_private_key(  # type: ignore
                    public_exponent=65537, key_size=int(params["key_size"])
                )
            elif key_type == "ED25519":
                private_key = ed25519.Ed25519PrivateKey.generate()
            else:
                raise logging.error(f"Key type not found or implemented {key_type}")

            self.storePrivateKey(
                certName=certName, private_key=private_key
            )  # type: ignore
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
            logging.info(f"Creating cert file for {certName}...")
            # but to create the cert, we need issuer key to sign it
            issuer_private_key = self.getPrivateKey(certName=issuer_name)
            # ok then we build the cert
            subject_name = certConf["subject_name"]
            ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
            cert = CertBuilder(certName=subject_name, conf=self.conf, ski=ski).builder
            cert = cert.public_key(private_key.public_key())
            # now sign the cert with the issuer private key
            hashAlg = self.conf.hashMapping[certConf["private_key"]["sign_with_alg"]]
            cert = cert.sign(
                private_key=issuer_private_key, algorithm=hashAlg
            )  # type: ignore
            # now store the cert
            self.storePublicKey(certName=certName, cert=cert)  # type: ignore
            logging.info(
                f"Cert created for {certName} with crt signed by {issuer_name}"
            )
        else:
            logging.info(f"Cert file already exists for {certName}")

        self._checkSignature(subjectName=certName, issuerName=issuer_name)

    def _checkSignature(self, subjectName: str, issuerName: str) -> None:
        # conf
        logging.info(f"checking signature of {subjectName}")
        issuerCrtFile = self.conf.getCertPath(
            certName=issuerName, ext="signed_certificate"
        )
        subjectCrtFile = self.conf.getCertPath(
            certName=subjectName, ext="signed_certificate"
        )

        # load certificates files
        issuer_public_key = ""
        subject_public_key = ""
        if issuerCrtFile != subjectCrtFile:
            issuer_public_key = loadFile(fileName=issuerCrtFile)
            subject_public_key = loadFile(fileName=subjectCrtFile)
        else:
            subject_public_key = loadFile(fileName=subjectCrtFile)
            issuer_public_key = subject_public_key

        # extract issuer and subject public keys
        issuer_cert_conf = self.conf.getCert(certName=issuerName)
        subject_cert_conf = self.conf.getCert(certName=subjectName)
        issuer_enc = issuer_cert_conf.get("public_key").get("encoding")
        subj_enc = subject_cert_conf.get("public_key").get("encoding")
        cert_to_check = ""

        if issuer_enc == "PEM":
            issuer_public_key = x509.load_pem_x509_certificate(
                issuer_public_key
            ).public_key()
        elif issuer_enc == "DER":
            issuer_public_key = x509.load_der_x509_certificate(
                issuer_public_key
            ).public_key()

        if subj_enc == "PEM":
            cert_to_check = x509.load_pem_x509_certificate(subject_public_key)
        if subj_enc == "DER":
            cert_to_check = x509.load_der_x509_certificate(subject_public_key)

        # checking now
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
                ec.ECDSA(cert_to_check.signature_hash_algorithm),
            )
        elif isinstance(issuer_public_key, ed25519.Ed25519PublicKey):
            issuer_public_key.verify(  # type: ignore
                cert_to_check.signature,
                cert_to_check.tbs_certificate_bytes,
            )
        else:
            raise logging.error(
                f"Failed to verify due to unsupported algorythm {type(cert_to_check.public_key())}"
            )

        logging.info(f"signature validated for {subjectName}")

    def _getParamsForPrivateBytes(
        self, certConf: Dict
    ) -> Tuple[serialization.Encoding, serialization.PrivateFormat]:
        encoding = self.conf.encodingMapping[certConf["private_key"]["encoding"]]
        key_format = self.conf.serializationMapping[
            certConf["private_key"]["serialization"]
        ]

        return encoding, key_format

    def _getEncryptionAlgorithm(
        self, passphrase: Optional[str] = None
    ) -> Union[serialization.BestAvailableEncryption, serialization.NoEncryption]:
        if passphrase:
            encryption_algorithm = serialization.BestAvailableEncryption(passphrase)
        else:
            encryption_algorithm = serialization.NoEncryption()

        return encryption_algorithm
