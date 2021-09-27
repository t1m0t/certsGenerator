import click
import logging

from src.certManager import CertManager


class CertsGenerator:
    def __init__(self, pathToConf: str, debug: bool):
        self.CONF_FILE = pathToConf
        logging_format = "%(levelname)s - %(message)s"
        if not debug:
            logging.basicConfig(level=logging.INFO, format=logging_format)
        else:
            logging.basicConfig(level=logging.DEBUG, format=logging_format)

    def run(self) -> None:
        cerManager = CertManager(confFile=self.CONF_FILE)
        for certConf in cerManager.conf.general.get("certs"):
            cerManager.createCerts(certName=certConf.get("name"))


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
        CertsGenerator(pathToConf=conf, debug=False).run()
    else:
        CertsGenerator(pathToConf=conf, debug=True).run()


if __name__ == "__main__":
    cli()
