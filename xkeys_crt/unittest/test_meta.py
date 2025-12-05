# coding:utf-8

from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import main

from xkeys_crt import meta


class TestGeneralName(TestCase):

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
        self.assertEqual(meta.GeneralName.resolve("localhost"), "127.0.0.1")
        self.assertEqual(meta.GeneralName.resolve("127.0.0.1"), "127.0.0.1")

    def test_load(self):
        self.assertIsInstance(gn := meta.GeneralName.load(self.options), meta.GeneralName)  # noqa:E501
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


class TestCustomCert(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.name = "example"
        cls.temp = TemporaryDirectory()
        meta.makedirs(data := meta.join(cls.temp.name, "backup"))
        meta.makedirs(conf := meta.join(cls.temp.name, "config"))
        meta.CustomCert.loadf(data, conf, cls.name).dumpf()
        cls.data: str = data
        cls.conf: str = conf

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.cert = meta.CustomCert.loadf(self.data, self.conf, self.name)
        self.assertIsInstance(self.cert["example.com"], meta.GeneralName)
        self.assertIsInstance(self.cert["localhost"], meta.GeneralName)

    def tearDown(self):
        pass

    def test_cached_cert(self):
        self.assertEqual(self.cert.cached_cert, meta.CustomCert.get_cached_cert(self.data, self.name))  # noqa:E501

    def test_delete(self):
        for general_name in self.cert:
            self.assertIsInstance(general_name, meta.GeneralName)
        self.assertIn("example.com", self.cert)
        self.assertIn("localhost", self.cert)
        self.assertEqual(len(self.cert), 2)
        self.assertTrue(self.cert.delete("example.com"))
        self.assertEqual(len(self.cert), 1)
        del self.cert["localhost"]
        self.assertEqual(len(self.cert), 0)


class TestCertConfig(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryDirectory()
        cls.path = meta.join(cls.temp.name, meta.CertConfig.DEFAULT_CONFIG)
        (cert := meta.CertConfig.loadf(cls.path)).dumpf()
        cert.lookup_cert("example").dumpf()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.cert = meta.CertConfig.loadf(self.path)

    def tearDown(self):
        pass

    def test_delete(self):
        for name in self.cert:
            self.assertEqual(name, "example")
        self.assertIn("example", self.cert)
        self.assertEqual(len(self.cert), 1)
        self.assertIsInstance(self.cert["example"], meta.CustomCert)
        del self.cert["example"]
        self.assertNotIn("example", self.cert)


if __name__ == "__main__":
    main()
