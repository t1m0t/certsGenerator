# certsGenerator
[![PYPI](https://img.shields.io/pypi/v/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
[![PYPI Python Versions](https://img.shields.io/pypi/pyversions/certsGenerator.svg)](https://pypi.org/project/certsGenerator/)
# About the project
This project:
 - aims to generate certificates from a json configuration file automatically. Just set the configuration properly and execute the script.
 - is built on top of https://github.com/pyca/cryptography
It is written in basic python (fonctionnal), but it works. I'll see wether to implement more tests and features in the future depending of the success of this project and contributions.
# Usage
 - install the package `pip install certsGenerator`
 - run the command, for example `certsGenerator --conf "example/conf.json"` (beware of relative file paths)

 # Testing
To run tests, run the command `pytest tests.py`