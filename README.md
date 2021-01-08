# certsGenerator
[![PYPI](https://img.shields.io/pypi/v/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
[![PYPI Python Versions](https://img.shields.io/pypi/pyversions/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
# About the project
This project:
 - aims to generate certificates from a json configuration file automatically. Just set the configuration properly and execute the script.
 - is built on top of https://github.com/pyca/cryptography
# Usage
 - install the package `pip install certsGenerator`
 - run the command, for example `certsGenerator --conf=certsData/conf.json"` (beware of relative file paths)
# Compatibility
Algorithms supported:
 * ECDSA
 * RSA

 # Testing
Run test with `pytest tests.py`.
