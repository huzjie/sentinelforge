# -*- coding: utf-8 -*-
import unittest

from sentinelforge.training.trainer import SkillTrainer


class TestTrainer(unittest.TestCase):
    def test_skill_increases(self):
        t = SkillTrainer(0.5, 0.05)
        step = t.train_step()
        self.assertGreater(step["skill"], 0.5)

    def test_recall_improves(self):
        t = SkillTrainer(0.5, 0.5)
        step = t.train_step()
        self.assertGreater(step["recall_after"], step["recall_before"])


if __name__ == "__main__":
    unittest.main()
