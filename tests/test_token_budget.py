# -*- coding: utf-8 -*-
import unittest

from sentinelforge.core.token_budget import TokenBudget
from sentinelforge.config import load_config


class TestTokenBudget(unittest.TestCase):
    def test_compress_truncates(self):
        cfg = load_config()
        cfg["engine"]["token_budget"] = 100
        tb = TokenBudget(cfg)
        text = "word " * 1000
        out, compressed = tb.compress(text)
        self.assertTrue(compressed)
        self.assertLess(tb.estimate(out), len(text) // 4)

    def test_no_compress_when_small(self):
        tb = TokenBudget(load_config())
        out, compressed = tb.compress("hello")
        self.assertFalse(compressed)


if __name__ == "__main__":
    unittest.main()
