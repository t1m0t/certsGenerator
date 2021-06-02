import sys
import logging
from os.path import exists


def loadFile(fileName: str) -> bytes:
    if exists(fileName):
        content = b""
        try:
            with open(fileName, mode="rb") as f:
                content = f.read()
        except OSError as e:
            sys.exit(f"failed to open {fileName}: {e}")

        if len(content) == 0:
            logging.error(f"File {fileName} is empty")
            raise ValueError()
            sys.exit()

        logging.debug(f"File {fileName} loaded with size of {len(content)} bytes")
        return content  # type: ignore
    else:
        logging.error(f"File {fileName} doesn't exist")
        raise ValueError()
        sys.exit()
