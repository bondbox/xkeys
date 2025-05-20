# coding:utf-8

from tempfile import TemporaryDirectory
import unittest
from unittest import mock

from xpw_keys import mkcert


class TestCertificate(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_load(self):
        self.assertRaises(FileNotFoundError, mkcert.Certificate.load, "test")


class TestMKCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rootca = mkcert.MKCert().rootCA
        if mkcert.exists(cls.rootca.crt_file):
            mkcert.remove(cls.rootca.crt_file)
        if mkcert.exists(cls.rootca.key_file):
            mkcert.remove(cls.rootca.key_file)
        cls.mkcert = mkcert.MKCert()
        cls.mkcert.reset()

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(mkcert, "exists", mock.MagicMock(side_effect=[False, True]))  # noqa:E501
    @mock.patch.object(mkcert, "isfile", mock.MagicMock(side_effect=[True]))  # noqa:E501
    @mock.patch.object(mkcert, "remove", mock.MagicMock())
    def test_which(self):
        with mock.patch.object(self.mkcert, "download") as mock_download:
            mock_download.side_effect = [Exception("download failed")]
            self.assertIsInstance(self.mkcert.which, str)

    def test_rootCA(self):
        self.assertIsInstance(root := self.mkcert.rootCA, mkcert.RootCA)
        self.assertEqual(str(root), f"Certificate(expire after {root.notAfterDays} days)")  # noqa:E501

    def test_generate(self):
        cert = self.mkcert.generate("example.com", "localhost", "127.0.0.1")
        self.assertIsInstance(cert, mkcert.Certificate)
        self.assertIsInstance(cert.crt, str)
        self.assertIsInstance(cert.key, str)
        self.assertIsInstance(cert.pem, str)
        with TemporaryDirectory() as tmpdir:
            cert.dump(path := mkcert.join(tmpdir, "test", "example"))
            self.assertRaises(FileExistsError, cert.dump, path=path)
            self.assertIsInstance(mkcert.Certificate.load(path), mkcert.Certificate)  # noqa:E501

    @mock.patch("urllib.request.urlretrieve", mock.MagicMock())
    def test_download(self):
        with TemporaryDirectory() as tmpdir:
            path: str = mkcert.join(tmpdir, "mkcert")
            with open(path, "w", encoding="utf-8") as whdl:
                whdl.write("unittest")
            self.assertIsNone(self.mkcert.download(file=path))


if __name__ == "__main__":
    unittest.main()
