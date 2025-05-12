# coding:utf-8

from os import chdir
from os.path import basename
from tempfile import TemporaryDirectory
import unittest

from xkits_key import ssh


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

    def test_generate(self):
        with TemporaryDirectory() as temp:
            key, pub = ssh.SSHKeyPair.generate(keyfile=temp)
            self.assertIsInstance(ssh.SSHKeyPair(key).fingerprint, str)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertTrue(ssh.SSHKeyPair.verify(key))
            key, pub = ssh.SSHKeyPair.generate(keyfile=temp)
            self.assertIsInstance(ssh.SSHKeyPair(key).fingerprint, str)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertTrue(ssh.SSHKeyPair.verify(key))

    def test_generate_auto(self):
        with TemporaryDirectory() as temp:
            chdir(temp)
            key, pub = ssh.SSHKeyPair.generate()
            self.assertIsInstance(ssh.SSHKeyPair(key).fingerprint, str)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertTrue(ssh.SSHKeyPair.verify(key))
            key, pub = ssh.SSHKeyPair.generate()
            self.assertIsInstance(ssh.SSHKeyPair(key).fingerprint, str)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertTrue(ssh.SSHKeyPair.verify(key))


class TestSSHKeys(unittest.TestCase):

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

    def test_generate_dir(self):
        with TemporaryDirectory() as temp:
            keys = ssh.SSHKeys(temp)
            self.assertEqual(len(keys), 0)
            key, pub = keys.generate()
            self.assertIn(basename(key), keys)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertEqual(len(keys), 1)
            key, pub = keys.generate()
            self.assertIn(basename(key), keys)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            self.assertEqual(len(keys), 2)

    def test_generate_file(self):
        with TemporaryDirectory() as temp:
            keys = ssh.SSHKeys(temp)
            self.assertEqual(len(keys), 0)
            key, pub = keys.generate(keyfile="unittest")
            self.assertIn("unittest", keys)
            self.assertEqual(len(keys), 1)
            self.assertEqual(key, ssh.join(keys.base, "unittest"))
            self.assertEqual(pub, ssh.join(keys.base, "unittest.pub"))
            self.assertRaises(FileExistsError, keys.generate, keyfile="unittest")  # noqa:E501
            self.assertEqual(len(keys), 1)


if __name__ == "__main__":
    unittest.main()
