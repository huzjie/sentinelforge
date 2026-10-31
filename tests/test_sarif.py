# -*- coding: utf-8 -*-
import json
import unittest

from sentinelforge.report.sarif import to_sarif
from sentinelforge.analyze.triage import TriagedFinding


class TestSarif(unittest.TestCase):
    def test_version(self):
        tf = TriagedFinding("sqli", "critical", 9.0, 0.9, 1, "x", "d", "r", None)
        doc = json.loads(to_sarif([tf]))
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)


if __name__ == "__main__":
    unittest.main()
