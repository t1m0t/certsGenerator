# certsGenerator
[![PYPI](https://img.shields.io/pypi/v/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
[![PYPI Python Versions](https://img.shields.io/pypi/pyversions/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
# About the project
This project:
 - aims to generate certificates from a json configuration file automatically. Just set the configuration properly and execute the script.
 - is built on top of https://github.com/pyca/cryptography
# Usage
 - install the package `pip install certsGenerator`
 - run the command, for example `certsGenerator --conf=certsData/conf.json"` (beware of relative file paths as the starting dir is from the one from which the program is executed)
# Compatibility
Algorithms supported:
 * ECDSA
 * RSA
 * Ed25519

OpenSSH keys format are supported as of v0.4.4

 # Testing
Run test with `pipenv run test`

# Contributing

Contributions are welcome. Feel free to participate!

1. First open a ticket issue
2. Push a PR eventually :)

# Licence

This program is licenced under MIT.