# -*- coding: utf-8 -*-
import unittest

from sentinelforge.core.modes import Modes
from sentinelforge.config import load_config


class TestModes(unittest.TestCase):
    def test_default_medium(self):
        m = Modes(load_config())
        self.assertEqual(m.mode, "medium")
        self.assertTrue(m.correlate_enabled())

    def test_high_deeper(self):
        cfg = load_config()
        cfg["engine"]["mode"] = "high"
        m = Modes(cfg)
        self.assertGreater(m.depth(), 2)
        self.assertGreater(m.budget_multiplier(), 1.0)


if __name__ == "__main__":
    unittest.main()
