# -*- coding: utf-8 -*-
"""Skill trainer: a monotonic, deterministic training loop.

Training a real model raises the fidelity with which it recovers the oracle
signal. Here that is represented by monotonically increasing ``skill``; each
step reports the resulting detection recall so the improvement is visible.
"""
from __future__ import annotations

from ..core.model import Model
from ..world.oracle import make_batch


class SkillTrainer:
    def __init__(self, skill=0.5, lr=0.05):
        self.skill = skill
        self.lr = lr
        self.batch = make_batch()

    def evaluate(self, skill=None):
        m = Model(self.skill if skill is None else skill)
        tp = fn = fp = 0
        for c in self.batch:
            flagged = m.flag(c["signal"], c["noise"])
            if c["is_true"] and flagged:
                tp += 1
            elif c["is_true"]:
                fn += 1
            elif flagged:
                fp += 1
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 1.0
        return {"recall": recall, "precision": precision, "tp": tp, "fn": fn, "fp": fp}

    def train_step(self):
        """One training step: skill increases monotonically toward 1.0."""
        before = self.evaluate()
        self.skill = min(1.0, self.skill + self.lr)
        after = self.evaluate()
        return {"skill": self.skill, "recall_before": before["recall"],
                "recall_after": after["recall"]}
