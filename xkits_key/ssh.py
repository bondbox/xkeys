# coding:utf-8

from enum import Enum
from os import listdir
from os import makedirs
from os import popen
from os import system
from os.path import dirname
from os.path import exists
from os.path import isdir
from os.path import isfile
from os.path import join
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple
from uuid import uuid4

from xkits_key.attribute import __project__


class SSHKeyType(Enum):
    RSA = "rsa"
    DSA = "dsa"
    ECDSA = "ecdsa"
    ECDSA_SK = "ecdsa-sk"
    ED25519 = "ed25519"
    ED25519_SK = "ed25519-sk"


class SSHKeyPair:
    def __init__(self, path: str):
        self.__private: str = path
        self.__public: str = f"{path}.pub"

    @property
    def private(self) -> str:
        """Private key file path"""
        return self.__private

    @property
    def public(self) -> str:
        """Public key file path"""
        return self.__public

    @property
    def fingerprint(self) -> str:
        """Fingerprint of the public key file"""
        return self.extract(self.public)[1]

    def __bool__(self) -> bool:
        if isfile(self.private) and isfile(self.public):
            try:
                with popen(f"ssh-keygen -y -f {self.private}") as phdl:
                    private: str = phdl.read().strip()
                    with open(self.public, encoding="utf-8") as rhdl:
                        public: str = rhdl.read().strip()
                        if private == public:
                            return True
            except Exception:  # pragma: no cover, pylint: disable=W0718
                pass  # pragma: no cover
        return False  # pragma: no cover

    @classmethod
    def verify(cls, path: str) -> bool:
        return bool(cls(path))

    @classmethod
    def extract(cls, keyfile: str) -> Tuple[int, str, str, str]:
        with popen(f"ssh-keygen -l -f {keyfile}") as phdl:
            output: List[str] = phdl.read().split()
            if len(output) != 4:
                raise ValueError(f"invalid key file: '{keyfile}'")  # noqa:E501, pragma: no cover
        bits: int = int(output[0])
        fingerprint: str = output[1].strip()
        comment: str = output[2].strip()
        keytype: str = output[3].strip().lstrip("(").rstrip(")")
        return bits, fingerprint, comment, keytype

    @classmethod
    def generate(cls,  # pylint: disable=R0913,R0917
                 bits: int = 4096,
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


class SSHKeys:
    def __init__(self, base: Optional[str] = None):
        self.__base: str = base or "."

    def __iter__(self) -> Iterator[str]:
        for item in listdir(self.base):
            if SSHKeyPair.verify(path := join(self.base, item)):
                yield path

    def __contains__(self, name: str) -> bool:
        return SSHKeyPair.verify(join(self.base, name))

    def __len__(self) -> int:
        return sum(1 for _ in self)

    @property
    def base(self) -> str:
        return self.__base

    def generate(self,  # pylint: disable=R0913,R0917
                 bits: int = 4096,
                 keytype: str = "rsa",
                 keyfile: Optional[str] = None,
                 comment: Optional[str] = None,
                 passphrase: Optional[str] = None
                 ) -> Tuple[str, str]:
        return SSHKeyPair.generate(bits=bits,
                                   keytype=keytype,
                                   keyfile=join(self.base, keyfile) if keyfile else self.base,  # noqa:E501
                                   comment=comment,
                                   passphrase=passphrase)


if __name__ == "__main__":
    key, pub = SSHKeyPair.generate()
    print(f"private key: {key}")
    print(f"public key:  {pub}")
    print(SSHKeyPair(key).fingerprint)
    print(SSHKeyPair.verify(key))
