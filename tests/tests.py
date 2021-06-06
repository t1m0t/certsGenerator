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
    def test_1_ecdsa(self) -> None:
        CONF_FILE = "tests/confs/test1.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        delDir("certs")

    def test_2_rsa(self) -> None:
        CONF_FILE = "tests/confs/test2.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        delDir("certs")

    def test_3_ed25119_cert(self) -> None:
        CONF_FILE = "tests/confs/test3.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        delDir("certs")
