import unittest

from src.main import CertsGenerator
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

    def test_4_ssh(self) -> None:
        CONF_FILE = "tests/confs/test4.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        delDir("certs")

    def test_5_partial_chain_check(self) -> None:
        CONF_FILE = "tests/confs/test5_1.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        CONF_FILE = "tests/confs/test5_2.json"
        CertsGenerator(pathToConf=CONF_FILE, debug=True).run()

        delDir("certs")
