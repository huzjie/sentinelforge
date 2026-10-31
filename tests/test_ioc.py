# -*- coding: utf-8 -*-
import unittest

from sentinelforge.detect.ioc import IocExtractor


class TestIoc(unittest.TestCase):
    def setUp(self):
        self.ex = IocExtractor()

    def _kinds(self, text):
        return [i.kind for i in self.ex.extract("f.txt", text)]

    def test_md5(self):
        self.assertIn("md5", self._kinds("d41d8cd98f00b204e9800998ecf8427e"))

    def test_url(self):
        self.assertIn("url", self._kinds("curl http://evil.example.com/x"))

    def test_sha256(self):
        self.assertIn("sha256", self._kinds("a" * 64))

    def test_public_ip(self):
        self.assertIn("ip", self._kinds("8.8.8.8"))


if __name__ == "__main__":
    unittest.main()
