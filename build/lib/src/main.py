from storage import loadConf
from storage import getFileExtensions
from builder import createCerts


if __name__ == "__main__":
    CONF_FILE = "../example/conf.json"
    generalConf = loadConf(CONF_FILE)
    fileExt = getFileExtensions(generalConf=generalConf)

    for certConf in generalConf["certs"]:
        createCerts(
            certConf=certConf["conf"], generalConf=generalConf, extensions=fileExt
        )
