# coding:utf-8

from tempfile import TemporaryDirectory
import unittest

from xpw_keys import config


class TestGeneralName(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.generalname = "example.com"
        cls.options = {"generalname": cls.generalname}

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_resolve(self):
        self.assertEqual(config.GeneralName.resolve("localhost"), "127.0.0.1")
        self.assertEqual(config.GeneralName.resolve("127.0.0.1"), "127.0.0.1")

    def test_load(self):
        self.assertIsInstance(gn := config.GeneralName.load(self.options), config.GeneralName)  # noqa:E501
        self.assertEqual(str(gn), f"GeneralName({gn.name})")
        self.assertEqual(gn.name, self.generalname)
        self.assertEqual(gn.options, self.options)
        self.assertEqual(len(gn.values), 1)
        self.assertFalse(gn.subdomains)
        self.assertFalse(gn.getaddress)
        self.assertTrue(gn.is_domain)
        gn.subdomains = True
        gn.getaddress = True
        self.assertIsInstance(gn.options, dict)
        self.assertEqual(len(gn.values), 3)
        self.assertTrue(gn.subdomains)
        self.assertTrue(gn.getaddress)


class TestCustomCert(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.name = "example"
        cls.temp = TemporaryDirectory()
        cls.path = config.join(cls.temp.name, cls.name)
        config.CustomCert.loadf(cls.path).dumpf()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.cert = config.CustomCert.loadf(self.path)
        self.assertIsInstance(self.cert["example.com"], config.GeneralName)
        self.assertIsInstance(self.cert["localhost"], config.GeneralName)

    def tearDown(self):
        pass

    def test_delete(self):
        for general_name in self.cert:
            self.assertIsInstance(general_name, config.GeneralName)
        self.assertIn("example.com", self.cert)
        self.assertIn("localhost", self.cert)
        self.assertEqual(len(self.cert), 2)
        self.assertTrue(self.cert.delete("example.com"))
        self.assertEqual(len(self.cert), 1)
        del self.cert["localhost"]
        self.assertEqual(len(self.cert), 0)


class TestCertConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory()
        cls.path = config.join(cls.temp.name, config.CertConfig.DEFAULT_CONFIG)
        (cert := config.CertConfig.loadf(cls.path)).dumpf()
        cert.create_cert("example").dumpf()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.cert = config.CertConfig.loadf(self.path)

    def tearDown(self):
        pass

    def test_delete(self):
        for name in self.cert:
            self.assertEqual(name, "example")
        self.assertIn("example", self.cert)
        self.assertEqual(len(self.cert), 1)
        self.assertIsInstance(self.cert["example"], config.CustomCert)
        del self.cert["example"]
        self.assertNotIn("example", self.cert)


if __name__ == "__main__":
    unittest.main()
