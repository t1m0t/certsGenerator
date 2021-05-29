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
 * Ed25519

 # Testing
Run test with `pipenv run test`

# Contributing

Contributions are welcome. Feel free to participate!

1. First open a ticket issue
2. Push a PR eventually :)

# Helpers
## Check certificate chain with openssl

From the generated certificates, it is possible to check the certificates like this:
 * Intermediate validated from Root `openssl verify -CAfile certs/root-ca/root-ca.crt certs/intermediate-ca/intermediate-ca.crt`
 * Postgres-ca validated from Intermediate `openssl verify -no-CAfile -no-CApath -partial_chain -trusted certs/intermediate-ca/intermediate-ca.crt certs/postgres-ca/postgres-ca.crt`
 * And so on down the chain

 If previous is OK and if the next crt's are OK as well, then it would mean that the chain is validated as they are linked to each other (Root > Intermediate > Leaf).

 This is a way to validate the certificates in case the configuration file not properly done but accepted by certsGenerator (normaly mistakes are triggered).