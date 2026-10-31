# -*- coding: utf-8 -*-
import unittest

from sentinelforge.core.engine import Engine
from sentinelforge.config import load_config
from sentinelforge.world.corpus import make_samples


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(load_config())

    def test_scan_produces_report(self):
        s = make_samples()[0]
        r = self.engine.scan(s["id"], s["text"])
        self.assertIn("findings", r["summary"])
        self.assertTrue(r["report"])
        self.assertTrue(r["sovereignty"]["offline"])

    def test_scan_sqli_sample(self):
        # the corpus's first sample is a SQLi; at skill 1.0 every true hit flags
        cfg = load_config()
        cfg["model"]["skill"] = 1.0
        engine = Engine(cfg)
        s = make_samples()[0]
        r = engine.scan(s["id"], s["text"])
        self.assertGreaterEqual(r["summary"]["findings"], 1)


if __name__ == "__main__":
    unittest.main()
