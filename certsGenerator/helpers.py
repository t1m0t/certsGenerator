import sys


def loadFile(fileName: str) -> bytes:
    content = b""
    try:
        with open(fileName, mode="rb") as f:
            content = f.read()
    except OSError as e:
        sys.exit(f"failed to open {fileName}: {e}")
    return content  # type: ignore
