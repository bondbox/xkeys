# coding:utf-8

from os import chdir
from tempfile import TemporaryDirectory
import unittest

from xkits_key import ssh


class TestSSH(unittest.TestCase):

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
            chdir(temp)
            key, pub = ssh.generate()
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            key, pub = ssh.generate()
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)

    def test_generate_dir(self):
        with TemporaryDirectory() as temp:
            key, pub = ssh.generate(keyfile=temp)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)
            key, pub = ssh.generate(keyfile=temp)
            self.assertIsInstance(key, str)
            self.assertIsInstance(pub, str)

    def test_generate_file(self):
        with TemporaryDirectory() as temp:
            file: str = ssh.join(temp, "unittest")
            key, pub = ssh.generate(keyfile=file)
            self.assertEqual(key, file)
            self.assertEqual(pub, f"{file}.pub")
            self.assertRaises(FileExistsError, ssh.generate, keyfile=file)


if __name__ == "__main__":
    unittest.main()
