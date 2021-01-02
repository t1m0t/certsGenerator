# certs_generator
[![PYPI](https://img.shields.io/pypi/v/certs_generator.svg)](https://pypi.org/project/certs-generator/)
[![PYPI Python Versions](https://img.shields.io/pypi/pyversions/certs_generator.svg)](https://pypi.org/project/certs-generator/)
# About the project
This project:
 - aims to generate certificates from a json configuration file automatically. Just set the configuration properly and execute the script.
 - is built on top of https://github.com/pyca/cryptography
It is written in basic python, with no tests or build pipeline yet, but it works. I'll see wether to implement such things in the future depending of the success of this project and contributions.
# Usage
 - configure in the configuration file mentionned in `main.py` via the variable `CONF_FILE`
 - execute the sript `python main.py` (be sure to be in the `src` directory)