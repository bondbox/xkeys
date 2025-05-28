# coding:utf-8

from tempfile import TemporaryDirectory
import unittest

from xpw_keys import crtkey


class TestCertificates(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.name = "example"
        cls.temp = TemporaryDirectory()
        cls.keys = crtkey.Certificates(cls.temp.name)
        if crtkey.exists("mkcert"):
            from shutil import copy2
            copy2("mkcert", crtkey.join(cls.keys.config.cached_cert, "mkcert"))

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.assertIsInstance(cert := self.keys.lookup(self.name), crtkey.Certificate)  # noqa:E501
        self.assertEqual(cert.lookup("example.com").name, "example.com")
        self.assertEqual(cert.lookup("localhost").name, "localhost")
        self.assertEqual(cert.lookup("127.0.0.1").name, "127.0.0.1")
        self.cert = cert

    def tearDown(self):
        pass

    def test_rootca(self):
        self.assertIsInstance(self.keys.rootca, crtkey.RootCA)

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
        self.assertIsInstance(self.cert.read(auto_generate=True), crtkey.CA)
        self.assertTrue(self.keys.delete(self.name))

    def test_read_validity(self):
        self.assertIsInstance(custom := self.keys.config.lookup_cert(self.name), crtkey.CustomCert)  # noqa:E501
        custom.validity = 1000
        self.assertEqual(custom.validity, 1000)
        cert = crtkey.Certificate(custom, crtkey.MKCert(self.keys.config.cached_cert))  # noqa:E501
        self.assertEqual(cert.lookup("example.com").name, "example.com")
        self.assertIsInstance(cert.read(auto_generate=True), crtkey.CA)
        self.assertIsInstance(cert.read(auto_generate=True), crtkey.CA)


if __name__ == "__main__":
    unittest.main()
