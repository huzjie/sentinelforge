# -*- coding: utf-8 -*-
import unittest

from sentinelforge.utils.yamlish import yaml_loads


class TestYamlish(unittest.TestCase):
    def test_scalars(self):
        d = yaml_loads("name: demo\nversion: 1\nratio: 0.5\nflag: true\nnothing: null\n")
        self.assertEqual(d["name"], "demo")
        self.assertEqual(d["version"], 1)
        self.assertEqual(d["ratio"], 0.5)
        self.assertTrue(d["flag"])
        self.assertIsNone(d["nothing"])

    def test_nested_map(self):
        d = yaml_loads("engine:\n  mode: medium\n  budget: 4096\n")
        self.assertEqual(d["engine"]["mode"], "medium")
        self.assertEqual(d["engine"]["budget"], 4096)

    def test_block_list(self):
        d = yaml_loads("rules:\n  - sqli\n  - xss\n  - cmdi\n")
        self.assertEqual(d["rules"], ["sqli", "xss", "cmdi"])

    def test_block_list_then_map(self):
        d = yaml_loads("detect:\n  rules:\n    - sqli\n    - xss\n  cve: true\n")
        self.assertEqual(d["detect"]["rules"], ["sqli", "xss"])
        self.assertTrue(d["detect"]["cve"])

    def test_inline_flow(self):
        d = yaml_loads("tags: [a, b, c]\nmap: {x: 1, y: 2}\n")
        self.assertEqual(d["tags"], ["a", "b", "c"])
        self.assertEqual(d["map"], {"x": 1, "y": 2})

    def test_comments_skipped(self):
        d = yaml_loads("# hi\nkey: value\n")
        self.assertEqual(d["key"], "value")


if __name__ == "__main__":
    unittest.main()
