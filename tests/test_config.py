# -*- coding: utf-8 -*-
import unittest

from sentinelforge.config import load_config, DEFAULTS


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config()
        self.assertEqual(cfg["engine"]["mode"], "medium")

    def test_merge_recipe(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("engine:\n  mode: high\n")
            path = f.name
        try:
            cfg = load_config(path)
            self.assertEqual(cfg["engine"]["mode"], "high")
            self.assertEqual(cfg["engine"]["token_budget"], DEFAULTS["engine"]["token_budget"])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
