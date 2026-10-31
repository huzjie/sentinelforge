# -*- coding: utf-8 -*-
import unittest

from sentinelforge.analyze.correlate import KillChain
from sentinelforge.analyze.triage import TriagedFinding


def _tf(rule_id, severity="high"):
    return TriagedFinding(rule_id, severity, 7.0, 0.9, 1, "x", "d", "r", None)


class TestCorrelate(unittest.TestCase):
    def test_stage_mapping(self):
        kc = KillChain()
        self.assertEqual(kc.stage_of("secrets"), "initial_access")
        self.assertEqual(kc.stage_of("sqli"), "execution")

    def test_correlate_buckets(self):
        kc = KillChain()
        chains = kc.correlate([_tf("secrets"), _tf("sqli"), _tf("pathtraversal")])
        stages = [s for s, fs in chains]
        self.assertIn("initial_access", stages)
        self.assertIn("execution", stages)

    def test_risk_score(self):
        kc = KillChain()
        score = kc.risk_score([_tf("sqli", "critical"), _tf("sqli", "critical")])
        self.assertGreater(score, 0)


if __name__ == "__main__":
    unittest.main()
