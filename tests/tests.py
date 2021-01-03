import unittest

from certsGenerator.storage import loadConf
from certsGenerator.storage import getFileExtensions
from certsGenerator.builder import createCerts

class MainTests(unittest.TestCase):
    def test_1_root_ca_certs_alone(self):
        CONF_FILE = "test1.json"
        generalConf = loadConf(CONF_FILE)
        fileExt = getFileExtensions(generalConf=generalConf)

        for certConf in generalConf["certs"]:
            createCerts(
                certConf=certConf["conf"],
                generalConf=generalConf,
                extensions=fileExt,
            )
