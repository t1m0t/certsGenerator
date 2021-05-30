import click
import logging

from certsGenerator.certManager import CertManager


class CertsGenerator:
    def __init__(self, pathToConf: str, debug: bool):
        self.CONF_FILE = pathToConf
        if debug:
            logging.basicConfig(level=logging.INFO, exc_info=False)
        else:
            logging.basicConfig(level=logging.DEBUG, exc_info=True)

    def run(self) -> None:
        cerManager = CertManager(confFile=self.CONF_FILE)
        for certConf in cerManager.conf.general["certs"]:
            cerManager.createCerts(certName=certConf["name"])


@click.command()
@click.option("--conf", "-c", default="data/conf.json", help="Certs configuration file")
@click.option(
    "--debug",
    "-d",
    default="false",
    help="Debug mode: true or false",
    type=click.Choice(["true", "false"]),
)
def cli(conf: str, debug: str) -> None:
    if debug == "false":
        CertsGenerator(pathToConf=conf).run()
    else:
        CertsGenerator(pathToConf=conf, debug=True).run()


if __name__ == "__main__":
    cli()
