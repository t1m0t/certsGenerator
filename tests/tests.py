import unittest
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec

from certsGenerator.storage import loadConf
from certsGenerator.storage import loadFile
from certsGenerator.storage import getFileExtensions
from certsGenerator.builder import createCerts

from .helpers import delDir


class MainTests(unittest.TestCase):
    def test_1_root_ca_generation(self):
        CONF_FILE = "test1.json"
        generalConf = loadConf(CONF_FILE)
        fileExt = getFileExtensions(generalConf=generalConf)

        for certConf in generalConf["certs"]:
            createCerts(
                certConf=certConf["conf"],
                generalConf=generalConf,
                extensions=fileExt,
            )
        delDir("certs")

    def test_2_1_root_and_intermediate_certificate_generation(self):
        CONF_FILE = "test2.json"
        generalConf = loadConf(CONF_FILE)
        fileExt = getFileExtensions(generalConf=generalConf)

        for certConf in generalConf["certs"]:
            createCerts(
                certConf=certConf["conf"],
                generalConf=generalConf,
                extensions=fileExt,
            )

    def test_2_2_check_intermediate_crt_signature(self):
        # conf
        issuerCrtFile = "certs/root-ca/root-ca.crt"
        intermediateCrtFile = "certs/intermadiate-ca/intermadiate-ca.crt"
        # load data
        pem_issuer_public_key = loadFile(fileName=issuerCrtFile)
        pem_intermediate_public_key = loadFile(fileName=intermediateCrtFile)
        # check
        issuer_public_key = x509.load_pem_x509_certificate(
            pem_issuer_public_key
        ).public_key()
        cert_to_check = x509.load_pem_x509_certificate(pem_intermediate_public_key)
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA512()),
        )

        delDir("certs")