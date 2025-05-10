# coding:utf-8

from os import makedirs
from os import system
from os.path import dirname
from os.path import exists
from os.path import isdir
from os.path import join
from typing import Optional
from typing import Tuple
from uuid import uuid4

from xkits_key.attribute import __project__


def generate(bits: int = 4096,
             keytype: str = "rsa",
             keyfile: Optional[str] = None,
             comment: Optional[str] = None,
             passphrase: Optional[str] = None
             ) -> Tuple[str, str]:
    if not keyfile:
        keyfile = str(uuid4())
    if exists(keyfile) and isdir(keyfile):
        keyfile = join(keyfile, str(uuid4()))
    makedirs(dirname(keyfile) or ".", mode=0o755, exist_ok=True)
    if not comment:
        comment = __project__
    if not passphrase:
        passphrase = "\"\""
    if exists(pubfile := f"{keyfile}.pub") or exists(keyfile):
        raise FileExistsError(f"private key '{keyfile}' or public key '{pubfile}' already exists")  # noqa:E501
    command: str = f"ssh-keygen -b {bits} -t {keytype} -f {keyfile} -C {comment} -N {passphrase}"  # noqa:E501
    if system(command) != 0:
        raise RuntimeError("failed to generate ssh key pair")  # noqa:E501, pragma: no cover
    assert exists(keyfile), f"private key '{keyfile}' not exists"
    assert exists(pubfile), f"public key '{pubfile}' not exists"
    return keyfile, pubfile


if __name__ == "__main__":
    key, pub = generate()
    print(f"keyfile: {key}")
    print(f"pubfile: {pub}")
