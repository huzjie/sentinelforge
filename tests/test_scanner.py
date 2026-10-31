# -*- coding: utf-8 -*-
import unittest

from sentinelforge.detect.scanner import Scanner
from sentinelforge.config import load_config


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = Scanner(load_config())

    def test_scan_finds_vuln(self):
        text = 'os.system("rm -rf " + path)\n'
        r = self.scanner.scan_text("app.py", text)
        self.assertTrue(any(f.rule_id == "cmdi" for f in r.findings))

    def test_fingerprint(self):
        r1 = self.scanner.scan_text("a.py", "x = 1")
        r2 = self.scanner.scan_text("b.py", "x = 1")
        self.assertEqual(r1.fingerprint, r2.fingerprint)

    def test_non_manifest_no_cves(self):
        r = self.scanner.scan_text("app.py", "import os\n")
        self.assertEqual(r.cves, [])


if __name__ == "__main__":
    unittest.main()
