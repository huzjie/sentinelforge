# -*- coding: utf-8 -*-
import unittest

from sentinelforge.analyze.triage import Triage
from sentinelforge.detect.rules import Finding
from sentinelforge.config import load_config


class TestTriage(unittest.TestCase):
    def test_triage_labels(self):
        t = Triage(load_config())
        f = Finding("sqli", "critical", 1, "x", "d", "r")
        out = t.triage(f, 0.9)
        # sqli base 9.0 * (0.5 + 0.5*0.9) = 8.55 -> high
        self.assertEqual(out.severity, "high")
        self.assertAlmostEqual(out.confidence, 0.9)

    def test_triage_critical_at_full_conf(self):
        t = Triage(load_config())
        f = Finding("cmdi", "critical", 1, "x", "d", "r")
        out = t.triage(f, 1.0)
        # cmdi base 9.5 * 1.0 = 9.5 -> critical
        self.assertEqual(out.severity, "critical")


if __name__ == "__main__":
    unittest.main()
