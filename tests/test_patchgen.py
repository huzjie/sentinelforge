# -*- coding: utf-8 -*-
import unittest

from sentinelforge.respond.patchgen import generate_patch
from sentinelforge.detect.rules import Finding


class TestPatchgen(unittest.TestCase):
    def test_expert_quality_one(self):
        f = Finding("sqli", "critical", 1, "x", "d", "r")
        patch, q = generate_patch(f, "use parameterized query", 1.0)
        self.assertAlmostEqual(q, 1.0)

    def test_no_gold_no_patch(self):
        f = Finding("sqli", "critical", 1, "x", "d", "r")
        patch, q = generate_patch(f, "", 1.0)
        self.assertEqual(patch, "")


if __name__ == "__main__":
    unittest.main()
