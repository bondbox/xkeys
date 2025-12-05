# coding:utf-8

from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import main
from unittest import mock

from xkeys_crt import make


class TestCertificate(TestCase):

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
        self.assertRaises(FileNotFoundError, make.CA.load, "test")


class TestMKCert(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rootca = make.MKCert().rootCA
        if make.exists(cls.rootca.crt_file):
            make.remove(cls.rootca.crt_file)
        if make.exists(cls.rootca.key_file):
            make.remove(cls.rootca.key_file)
        cls.mkcert = make.MKCert()
        cls.mkcert.reset()

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    @mock.patch.object(make, "exists", mock.MagicMock(side_effect=[False, True, False]))  # noqa:E501
    @mock.patch.object(make, "isfile", mock.MagicMock(side_effect=[True]))  # noqa:E501
    @mock.patch.object(make, "remove", mock.MagicMock())
    def test_which(self):
        with mock.patch.object(self.mkcert, "download") as mock_download:
            def which() -> str:
                return self.mkcert.which

            mock_download.side_effect = [Exception("download failed")]
            self.assertRaises(FileNotFoundError, which)

    def test_rootCA(self):
        self.assertIsInstance(root := self.mkcert.rootCA, make.RootCA)
        self.assertEqual(str(root), f"CA(expire after {root.notAfterDays} days)")  # noqa:E501

    def test_generate(self):
        cert = self.mkcert.generate("example.com", "localhost", "127.0.0.1")
        self.assertIsInstance(cert, make.CA)
        self.assertIsInstance(cert.crt, str)
        self.assertIsInstance(cert.key, str)
        self.assertIsInstance(cert.pem, str)
        self.assertEqual(cert.general_names, ["example.com", "localhost", "127.0.0.1"])  # noqa:E501
        with TemporaryDirectory() as tmpdir:
            cert.dump(path := make.join(tmpdir, "test", "example"))
            self.assertRaises(FileExistsError, cert.dump, path=path)
            self.assertIsInstance(make.CA.load(path), make.CA)

    @mock.patch("urllib.request.urlretrieve", mock.MagicMock())
    def test_download(self):
        with TemporaryDirectory() as tmpdir:
            path: str = make.join(tmpdir, "mkcert")
            with open(path, "w", encoding="utf-8") as whdl:
                whdl.write("unittest")
            self.assertIsNone(self.mkcert.download(file=path))


if __name__ == "__main__":
    main()
