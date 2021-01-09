import click

from certsGenerator.certManager import CertManager


class CertsGenerator:
    def __init__(self, pathToConf: str):
        self.CONF_FILE = pathToConf

    def run(self) -> None:
        cerManager = CertManager(confFile=self.CONF_FILE)
        for certConf in cerManager.conf.general["certs"]:
            cerManager.createCerts(certName=certConf["name"])


@click.command()
@click.option("--conf", default="data/conf.json", help="Certs configuration file")
def cli(conf: str) -> None:
    CertsGenerator(pathToConf=conf).run()


if __name__ == "__main__":
    cli()
