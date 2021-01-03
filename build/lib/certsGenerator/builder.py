import os
import stat

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from certsGenerator.storage import getPrivateKey
from certsGenerator.storage import getCertConf
from certsGenerator.storage import storePublicKey

from certsGenerator.constructor import setNameAttributes
from certsGenerator.constructor import setNotValid
from certsGenerator.constructor import setExtensions

from certsGenerator.globals_conf import curveMapping
from certsGenerator.globals_conf import hash_mapping


def buildCerticate(
    generalConf: dict, certName: str, key: ec.EllipticCurvePrivateKey
) -> x509.Certificate:
    certConf = getCertConf(generalConf=generalConf, certName=certName)

    certBuilder = x509.CertificateBuilder()
    certBuilder = setNameAttributes(
        generalConf=generalConf, certName=certName, builder=certBuilder
    )
    certBuilder = setNotValid(
        generalConf=generalConf, certName=certName, builder=certBuilder
    )
    certBuilder = setExtensions(
        generalConf=generalConf, certName=certName, builder=certBuilder, key=key
    )
    certBuilder = certBuilder.serial_number(x509.random_serial_number())
    certBuilder = certBuilder.public_key(key.public_key())
    hashAlg = hash_mapping[certConf["private_key"]["sign_with_alg"]]
    cert = certBuilder.sign(private_key=key, algorithm=hashAlg)  # type: ignore

    return cert


def createCerts(certConf: dict, generalConf: dict, extensions: dict) -> None:
    # get the private key (created if it doesn't exist yet)
    private_key = getPrivateKey(certConf=certConf, extensions=extensions)

    # regarding cert
    path = certConf["storage"]["path"]
    fileName = certConf["storage"]["fileName"]
    crtExt = extensions["crt"]
    certFile = f"{path}/{fileName}.{crtExt}"
    # check if cert exists
    if not os.path.exists(certFile):
        # but to create the cert, we need issuer key
        issuer_name = certConf["issuer_name"]
        issuerConf = getCertConf(generalConf=generalConf, certName=issuer_name)
        issuer_private_key = getPrivateKey(certConf=issuerConf, extensions=extensions)
        # ok then we build the cert
        subject_name = certConf["subject_name"]
        cert = buildCerticate(
            generalConf=generalConf,
            certName=subject_name,
            key=issuer_private_key,
        )

        storePublicKey(path=certFile, cert=cert)
