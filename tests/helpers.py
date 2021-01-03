import pathlib


def delDir(path: str):
    pth = pathlib.Path(path)
    for sub in pth.iterdir():
        if sub.is_dir():
            delDir(sub)
        else:
            sub.unlink()
    pth.rmdir()
