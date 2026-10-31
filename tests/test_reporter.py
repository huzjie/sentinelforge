# -*- coding: utf-8 -*-
import unittest

from sentinelforge.report.reporter import Reporter
from sentinelforge.config import load_config


class TestReporter(unittest.TestCase):
    def test_markdown(self):
        r = Reporter(load_config())
        md = r.render_markdown({"findings": 2}, [], [])
        self.assertIn("Sentinelforge", md)

    def test_json(self):
        r = Reporter(load_config())
        js = r.render_json({"findings": 2}, [], [])
        self.assertIn('"findings"', js)


if __name__ == "__main__":
    unittest.main()
