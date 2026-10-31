# -*- coding: utf-8 -*-
import unittest

from sentinelforge.analyze.severity import score_to_label, cvss_score


class TestSeverity(unittest.TestCase):
    def test_labels(self):
        self.assertEqual(score_to_label(9.5), "critical")
        self.assertEqual(score_to_label(8.0), "high")
        self.assertEqual(score_to_label(5.0), "medium")
        self.assertEqual(score_to_label(2.0), "low")
        self.assertEqual(score_to_label(0.1), "info")

    def test_cvss_conf_monotonic(self):
        self.assertGreater(cvss_score("sqli", 0.9), cvss_score("sqli", 0.3))


if __name__ == "__main__":
    unittest.main()
