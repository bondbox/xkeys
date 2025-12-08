# coding:utf-8

from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest import main

from xkeys_ssh import ring


class TestSSHKeyRing(TestCase):

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
            keys = ring.SSHKeyRing(temp)
            self.assertEqual(len(keys), 0)
            self.assertIsInstance(name := keys.generate(), str)
            self.assertIsInstance(item := keys[name], ring.SSHKeyPair)
            self.assertEqual(len(keys), 1)
            self.assertRaises(FileExistsError, keys.create, item.private)
            self.assertRaises(FileExistsError, keys.update, name, item.private)
            self.assertIsNone(keys.update(name, ring.SSHKeyPair.generate().private))  # noqa:E501
            self.assertIsInstance(item := keys[name], ring.SSHKeyPair)
            self.assertEqual(len(keys), 1)
            self.assertTrue(keys.rename(name, "test"))
            self.assertIsInstance(item := keys["test"], ring.SSHKeyPair)
            self.assertEqual(len(keys), 1)
            self.assertTrue(keys.remove("test"))
            self.assertNotIn("test", keys)
            self.assertEqual(len(keys), 0)
            del keys["test"]
            self.assertEqual(len(keys), 0)


if __name__ == "__main__":
    main()
