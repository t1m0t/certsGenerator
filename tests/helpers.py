import pathlib

from typing import Union


def delDir(path: Union[str, pathlib.Path]) -> None:
    pth = pathlib.Path(path)
    for sub in pth.iterdir():
        if sub.is_dir():
            delDir(sub)
        else:
            sub.unlink()
    pth.rmdir()
