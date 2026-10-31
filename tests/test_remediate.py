# -*- coding: utf-8 -*-
import unittest

from sentinelforge.respond.remediate import remediation_plan
from sentinelforge.analyze.triage import TriagedFinding


def _tf(severity):
    return TriagedFinding("sqli", severity, 9.0, 0.9, 1, "x", "d", "fix it", None)


class TestRemediate(unittest.TestCase):
    def test_sorted_by_priority(self):
        plan = remediation_plan([_tf("low"), _tf("critical"), _tf("high")])
        self.assertEqual(plan[0]["severity"], "critical")
        self.assertEqual(plan[-1]["severity"], "low")


if __name__ == "__main__":
    unittest.main()
