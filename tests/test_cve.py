# -*- coding: utf-8 -*-
import unittest

from sentinelforge.detect.cve import CveMatcher, version_lt


class TestCve(unittest.TestCase):
    def setUp(self):
        self.m = CveMatcher()

    def test_log4shell(self):
        hits = self.m.match_manifest("requirements.txt", "log4j-core==2.14.0\n")
        self.assertTrue(any(h["cve"] == "CVE-2021-44228" for h in hits))

    def test_log4j_fixed_not_vulnerable(self):
        hits = self.m.match_manifest("requirements.txt", "log4j-core==2.15.0\n")
        self.assertFalse(any(h["cve"] == "CVE-2021-44228" for h in hits))

    def test_xz_range(self):
        hits = self.m.match_manifest("requirements.txt", "xz==5.6.1\n")
        self.assertTrue(any(h["cve"] == "CVE-2024-3094" for h in hits))

    def test_non_manifest(self):
        self.assertEqual(self.m.match_manifest("app.py", "log4j-core==2.14.0"), [])

    def test_version_lt(self):
        self.assertTrue(version_lt("2.14.0", "2.15.0"))
        self.assertFalse(version_lt("2.15.0", "2.14.0"))


if __name__ == "__main__":
    unittest.main()
