# -*- coding: utf-8 -*-
import unittest

from sentinelforge.detect.rules import RuleEngine


class TestRules(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def _find(self, text):
        return [f.rule_id for f in self.engine.scan(text)]

    def test_sqli_concat(self):
        text = """query = "SELECT * FROM users WHERE name = '" + username + "'"
"""
        self.assertIn("sqli", self._find(text))

    def test_sqli_fstring(self):
        text = 'q = f"SELECT * FROM users WHERE id = {uid}"\n'
        self.assertIn("sqli", self._find(text))

    def test_cmdi(self):
        text = 'os.system("ping -c 1 " + host)\n'
        self.assertIn("cmdi", self._find(text))

    def test_xss(self):
        text = 'el.innerHTML += comment;\n'
        self.assertIn("xss", self._find(text))

    def test_secret(self):
        text = 'API_KEY = "sk-live-abcdefghijklmnopqrst"\n'
        self.assertIn("secrets", self._find(text))

    def test_weakcrypto(self):
        text = 'return hashlib.md5(pw.encode()).hexdigest()\n'
        self.assertIn("weakcrypto", self._find(text))

    def test_clean_code_no_findings(self):
        text = 'def add(a, b):\n    return a + b\n'
        self.assertEqual(self._find(text), [])


if __name__ == "__main__":
    unittest.main()
