# coding:utf-8

from tempfile import TemporaryDirectory
import unittest

from xpw_keys import sshkey


class TestSSHKeyPair(unittest.TestCase):

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
        item = sshkey.SSHKeyPair.generate(bits=512)
        self.assertIsInstance(item, sshkey.SSHKeyPair)
        self.assertIsInstance(item.bits, int)
        self.assertIsInstance(item.type, str)
        self.assertIsInstance(item.comment, str)
        self.assertIsInstance(item.fingerprint, str)
        self.assertIsInstance(item.private, str)
        self.assertIsInstance(item.public, str)
        self.assertEqual(str(item), item.fingerprint)
        self.assertEqual(item.bits, 1024)

    def test_generate_dsa(self):
        item = sshkey.SSHKeyPair.generate(type="dsa", bits=4096)
        self.assertIsInstance(item, sshkey.SSHKeyPair)
        self.assertIsInstance(item.bits, int)
        self.assertIsInstance(item.type, str)
        self.assertIsInstance(item.comment, str)
        self.assertIsInstance(item.fingerprint, str)
        self.assertIsInstance(item.private, str)
        self.assertIsInstance(item.public, str)
        self.assertEqual(str(item), item.fingerprint)
        self.assertEqual(item.bits, 1024)

    def test_generate_type_error(self):
        self.assertRaises(ValueError, sshkey.SSHKeyPair.generate, type="RSA")

    def test_generate_ecdsa_bits_error(self):
        self.assertRaises(ValueError, sshkey.SSHKeyPair.generate, type="ecdsa", bits=128)  # noqa:E501

    def test_dump(self):
        item = sshkey.SSHKeyPair.generate()
        self.assertIsInstance(item, sshkey.SSHKeyPair)
        with TemporaryDirectory() as temp:
            self.assertIsNone(item.dump(path := sshkey.join(temp, "test", "demo")))  # noqa:E501
            self.assertRaises(FileExistsError, item.dump, path)

    def test_load(self):
        self.assertRaises(FileNotFoundError, sshkey.SSHKeyPair.load, "test")


class TestSSHKeyRing(unittest.TestCase):

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

    def test_all_in_one(self):
        with TemporaryDirectory() as temp:
            keys = sshkey.SSHKeyRing(temp)
            self.assertEqual(len(keys), 0)
            self.assertIsInstance(name := keys.generate(), str)
            self.assertIsInstance(item := keys[name], sshkey.SSHKeyPair)
            self.assertEqual(len(keys), 1)
            self.assertIsInstance(name := keys.create(item.private), str)
            self.assertIsInstance(item := keys[name], sshkey.SSHKeyPair)
            self.assertEqual(len(keys), 2)
            self.assertIsNone(keys.update(name, item.private))
            self.assertIsInstance(item := keys[name], sshkey.SSHKeyPair)
            self.assertEqual(len(keys), 2)
            self.assertTrue(keys.rename(name, "test"))
            self.assertIsInstance(item := keys["test"], sshkey.SSHKeyPair)
            self.assertEqual(len(keys), 2)
            self.assertTrue(keys.remove("test"))
            self.assertNotIn("test", keys)
            self.assertEqual(len(keys), 1)
            del keys["test"]
            self.assertEqual(len(keys), 1)


if __name__ == "__main__":
    unittest.main()
