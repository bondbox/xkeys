# coding:utf-8

from os import makedirs
from os.path import abspath
from os.path import dirname
from os.path import exists
from os.path import isfile
from os.path import join
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple


class GeneralName:
    def __init__(self, domain_or_address: str, subdomains: bool = False, getaddress: bool = False):  # noqa:E501
        name, is_domain = self.format(domain_or_address)
        self.__subdomains: bool = is_domain and subdomains
        self.__getaddress: bool = is_domain and getaddress
        self.__is_domain: bool = is_domain
        self.__name: str = name

    def __str__(self) -> str:
        return f"{__class__.__name__}({self.name})"

    @property
    def name(self) -> str:
        return self.__name

    @property
    def is_domain(self) -> bool:
        return self.__is_domain

    @property
    def subdomains(self) -> bool:
        return self.__subdomains

    @subdomains.setter
    def subdomains(self, value: bool) -> None:
        self.__subdomains = self.is_domain and value

    @property
    def getaddress(self) -> bool:
        return self.__getaddress

    @getaddress.setter
    def getaddress(self, value: bool) -> None:
        self.__getaddress = self.is_domain and value

    @property
    def options(self) -> Dict[str, Any]:
        options: Dict[str, Any] = {"generalname": self.name}
        if self.subdomains:
            options["subdomains"] = True
        if self.getaddress:
            options["getaddress"] = True
        return options

    @property
    def values(self) -> List[str]:
        values: List[str] = [self.name]
        if self.subdomains:
            values.append(f"*.{self.name}")
        if self.getaddress:
            values.append(self.resolve(self.name))
        return values

    @classmethod
    def format(cls, domain_or_address: str) -> Tuple[str, bool]:
        try:
            from ipaddress import ip_address  # pylint: disable=C0415
            return str(ip_address(domain_or_address)), False
        except ValueError:
            return domain_or_address, True

    @classmethod
    def resolve(cls, domain_name: str) -> str:
        """resolve domain name"""
        from socket import gethostbyname  # pylint: disable=C0415
        return gethostbyname(domain_name)

    @classmethod
    def load(cls, options: Dict[str, Any]):
        subdomains: bool = options.get("subdomains", False)
        getaddress: bool = options.get("getaddress", False)
        return cls(options["generalname"], subdomains, getaddress)


class CustomCert:
    ALTNAME: str = "SubjectAlternativeName"

    def __init__(self, path: str, data: Dict[str, Any]):
        items: List[GeneralName] = [GeneralName.load(i) for i in data.get(self.ALTNAME, [])]   # noqa:E501
        self.__names: Dict[str, GeneralName] = {gn.name: gn for gn in items}
        self.__path: str = abspath(path)

    def __iter__(self) -> Iterator[GeneralName]:
        return iter(self.__names.values())

    def __len__(self) -> int:
        return len(self.__names)

    def __delitem__(self, name: str):
        self.delete(name)

    def __getitem__(self, name: str) -> GeneralName:
        return self.lookup(name)

    def __contains__(self, name: str) -> bool:
        return name in self.__names

    @property
    def path(self) -> str:
        return self.__path

    def lookup(self, name: str) -> GeneralName:
        if name not in self.__names:
            self.__names.setdefault(name, GeneralName(name))
        return self.__names[name]

    def delete(self, name: str) -> bool:
        if name in self.__names:
            del self.__names[name]
        return name not in self.__names

    def dumps(self) -> str:
        from toml import dumps  # pylint: disable=import-outside-toplevel
        return dumps({self.ALTNAME: [gn.options for gn in self.__names.values()]})  # noqa:E501

    def dumpf(self, path: Optional[str] = None) -> None:
        from xkits_file import SafeWrite  # pylint: disable=C0415
        with SafeWrite(path or self.path, encoding="utf-8", truncate=True) as whdl:  # noqa:E501
            whdl.write(self.dumps())

    @classmethod
    def loadf(cls, path: str) -> "CustomCert":
        if not exists(path):
            return cls(path=path, data={})

        from toml import loads  # pylint: disable=import-outside-toplevel
        from xkits_file import SafeRead  # pylint: disable=C0415

        with SafeRead(path, encoding="utf-8") as rhdl:
            return cls(path=path, data=loads(rhdl.read()))


class CertConfig:
    DEFAULT_CONFIG: str = "certificates.toml"
    CUSTOM_CERT: str = "custom_cert"
    GLOBAL_NAME: str = "globals"

    def __init__(self, path: str, data: Dict[str, Any]):
        path = abspath(path)
        custom_cert: str = data.get(self.CUSTOM_CERT, join(dirname(path), "custom"))  # noqa:E501
        global_name: List = data.get(self.GLOBAL_NAME, [])
        makedirs(custom_cert, mode=0o740, exist_ok=True)

        self.__global_name: List[str] = global_name
        self.__custom_cert: str = custom_cert
        self.__path: str = path

    def __iter__(self) -> Iterator[str]:
        from os import listdir  # pylint: disable=import-outside-toplevel
        for name in listdir(self.custom_cert):
            if isfile(self.join(name)):
                yield name

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def __delitem__(self, name: str):
        self.delete_cert(name)

    def __getitem__(self, name: str) -> CustomCert:
        return CustomCert.loadf(self.join(name))

    def __contains__(self, name: str) -> bool:
        return exists(self.join(name))

    def join(self, name: str) -> str:
        return join(self.custom_cert, name)

    @property
    def path(self) -> str:
        return self.__path

    @property
    def global_name(self) -> List[str]:
        return self.__global_name

    @property
    def custom_cert(self) -> str:
        return self.__custom_cert

    def create_cert(self, name: str) -> CustomCert:
        assert name not in self, f"name '{name}' already exists"
        return CustomCert.loadf(self.join(name))

    def delete_cert(self, name: str) -> bool:
        if name in self:
            from os import remove  # pylint: disable=import-outside-toplevel
            remove(self.join(name))
        return name not in self

    def dumps(self) -> str:
        from toml import dumps  # pylint: disable=import-outside-toplevel
        return dumps({self.CUSTOM_CERT: self.custom_cert, self.GLOBAL_NAME: self.global_name})  # noqa:E501

    def dumpf(self, path: Optional[str] = None) -> None:
        from xkits_file import SafeWrite  # pylint: disable=C0415
        with SafeWrite(path or self.path, encoding="utf-8", truncate=True) as whdl:  # noqa:E501
            whdl.write(self.dumps())

    @classmethod
    def loadf(cls, path: str = DEFAULT_CONFIG) -> "CertConfig":
        if not exists(path):
            return cls(path=path, data={})

        from toml import loads  # pylint: disable=import-outside-toplevel
        from xkits_file import SafeRead  # pylint: disable=C0415

        with SafeRead(path, encoding="utf-8") as rhdl:
            return cls(path=path, data=loads(rhdl.read()))


if __name__ == "__main__":
    print(GeneralName.resolve("localhost"))
    print(GeneralName.resolve("127.0.0.1"))
    CustomCert.loadf("example.toml").dumpf()
    CertConfig.loadf().dumpf()
