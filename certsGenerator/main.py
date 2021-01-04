import click

from certsGenerator.storage import loadConf
from certsGenerator.storage import getFileExtensions
from certsGenerator.builder import createCerts


class CertsGenerator():
    def __init__(self, pathToConf:str):
        self.CONF_FILE = "example/conf.json"
    
    def run(self):
        generalConf = loadConf(self.CONF_FILE)
        fileExt = getFileExtensions(generalConf=generalConf)
        for certConf in generalConf["certs"]:
            createCerts(
                certConf=certConf["conf"],
                generalConf=generalConf,
                extensions=fileExt,
            )

@click.command()
@click.option('--conf', default="example/conf.json",help="Certs configuration file")
def cli(conf):
    CertsGenerator(pathToConf=conf).run()


if __name__ == "__main__":
    cli()
