# coding:utf-8

from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import main

from xkeys_crt import cert


class TestCertificates(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.name = "example"
        cls.temp = TemporaryDirectory()
        cls.keys = cert.Certificates(cls.temp.name)
        if cert.exists("mkcert"):
            from shutil import copy2
            copy2("mkcert", cert.join(cls.keys.config.cached_cert, "mkcert"))

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.assertIsInstance(crt := self.keys.lookup(self.name), cert.Certificate)  # noqa:E501
        self.assertEqual(crt.lookup("example.com").name, "example.com")
        self.assertEqual(crt.lookup("localhost").name, "localhost")
        self.assertEqual(crt.lookup("127.0.0.1").name, "127.0.0.1")
        self.cert = crt

    def tearDown(self):
        pass

    def test_rootca(self):
        self.assertIsInstance(self.keys.rootca, cert.RootCA)

    def test_save(self):
        self.assertTrue(self.keys.delete(self.name))
        self.assertTrue(self.cert.save())
        self.assertTrue(self.keys.delete(self.name))

    def test_delete_general_name(self):
        self.assertTrue(self.cert.delete("example.com"))
        self.assertTrue(self.cert.delete("localhost"))
        self.assertTrue(self.cert.delete("127.0.0.1"))
        self.assertTrue(self.cert.delete("unittest"))
        self.assertRaises(ValueError, self.cert.read)

    def test_read(self):
        self.assertRaises(FileNotFoundError, self.cert.read)
        self.assertIsInstance(self.cert.read(auto_generate=True), cert.CA)
        self.assertTrue(self.keys.delete(self.name))

    def test_read_validity(self):
        self.assertIsInstance(custom := self.keys.config.lookup_cert(self.name), cert.CustomCert)  # noqa:E501
        custom.validity = 1000
        self.assertEqual(custom.validity, 1000)
        crt = cert.Certificate(custom, cert.MKCert(self.keys.config.cached_cert))  # noqa:E501
        self.assertEqual(crt.lookup("example.com").name, "example.com")
        self.assertIsInstance(crt.read(auto_generate=True), cert.CA)
        self.assertIsInstance(crt.read(auto_generate=True), cert.CA)


if __name__ == "__main__":
    main()
