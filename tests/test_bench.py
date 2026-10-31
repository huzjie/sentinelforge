# -*- coding: utf-8 -*-
import unittest

from sentinelforge import bench


class TestBench(unittest.TestCase):
    def test_monotonic(self):
        rows = bench.run_all()
        self.assertGreater(rows[-1]["detect_recall"], rows[0]["detect_recall"])
        self.assertLess(rows[-1]["false_positive_rate"], rows[0]["false_positive_rate"])
        self.assertGreater(rows[-1]["triage_accuracy"], rows[0]["triage_accuracy"])
        self.assertGreater(rows[-1]["remediation_quality"], rows[0]["remediation_quality"])

    def test_expert_recall_one(self):
        rows = bench.run_all([1.0])
        self.assertAlmostEqual(rows[0]["detect_recall"], 1.0)


if __name__ == "__main__":
    unittest.main()
