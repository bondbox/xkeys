# coding:utf-8

from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import main

from xkeys_ssh import ring


class TestSSHKeyPair(TestCase):

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

    def test_generate_rsa(self):
        item = ring.SSHKeyPair.generate(bits=512)
        self.assertIsInstance(item, ring.SSHKeyPair)
        self.assertIsInstance(item.algo, str)
        self.assertIsInstance(item.bits, int)
        self.assertIsInstance(item.comment, str)
        self.assertIsInstance(item.fingerprint, str)
        self.assertIsInstance(item.private, str)
        self.assertIsInstance(item.public, str)
        self.assertEqual(str(item), item.fingerprint)
        self.assertEqual(item.bits, 1024)

    def test_generate_dsa(self):
        item = ring.SSHKeyPair.generate(algo="dsa", bits=4096)
        self.assertIsInstance(item, ring.SSHKeyPair)
        self.assertIsInstance(item.algo, str)
        self.assertIsInstance(item.bits, int)
        self.assertIsInstance(item.comment, str)
        self.assertIsInstance(item.fingerprint, str)
        self.assertIsInstance(item.private, str)
        self.assertIsInstance(item.public, str)
        self.assertEqual(str(item), item.fingerprint)
        self.assertEqual(item.bits, 1024)

    def test_generate_type_error(self):
        self.assertRaises(ValueError, ring.SSHKeyPair.generate, algo="RSA")

    def test_generate_ecdsa_bits_error(self):
        self.assertRaises(ValueError, ring.SSHKeyPair.generate, algo="ecdsa", bits=128)  # noqa:E501

    def test_dump(self):
        item = ring.SSHKeyPair.generate()
        self.assertIsInstance(item, ring.SSHKeyPair)
        with TemporaryDirectory() as temp:
            self.assertIsNone(item.dump(path := ring.join(temp, "test", "demo")))  # noqa:E501
            self.assertRaises(FileExistsError, item.dump, path)

    def test_load(self):
        self.assertRaises(FileNotFoundError, ring.SSHKeyPair.load, "test")


if __name__ == "__main__":
    main()
