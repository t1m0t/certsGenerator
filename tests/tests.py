import unittest
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec

from certsGenerator.main import CertsGenerator
from certsGenerator.helpers import loadFile

from tests.helpers import delDir


class MainTests(unittest.TestCase):
    def test_1_ecdsa_root_ca_generation(self) -> None:
        CONF_FILE = "test1.json"
        CertsGenerator(pathToConf=CONF_FILE).run()

        delDir("certs")

    def test_2_1_ecdsa_root_and_intermediate_certificate_generation(self) -> None:
        CONF_FILE = "test2.json"
        CertsGenerator(pathToConf=CONF_FILE).run()

        delDir("certs")

    def test_3_1_rsa_certs(self) -> None:
        CONF_FILE = "test3.json"
        CertsGenerator(pathToConf=CONF_FILE).run()

        delDir("certs")
