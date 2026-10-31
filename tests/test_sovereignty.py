# -*- coding: utf-8 -*-
import unittest

from sentinelforge.core.sovereignty import Sovereignty


class TestSovereignty(unittest.TestCase):
    def test_offline_ok(self):
        s = Sovereignty(True)
        self.assertTrue(s.assert_offline())
        self.assertEqual(s.audit()["network_egress"], 0)

    def test_online_raises(self):
        s = Sovereignty(False)
        with self.assertRaises(RuntimeError):
            s.assert_offline()


if __name__ == "__main__":
    unittest.main()
