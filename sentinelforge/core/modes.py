# -*- coding: utf-8 -*-
"""Reasoning modes: three inference depths selected by budget, not by prompt.

Mirrors Mistral Large 4's low / medium / high inference modes. The signal
(prompt + code) is identical; only the effort budget changes.
"""
from __future__ import annotations

MODES = {
    "low":    {"depth": 1, "budget_mult": 0.4, "correlate": False, "patch": False, "label": "fast triage"},
    "medium": {"depth": 2, "budget_mult": 1.0, "correlate": True,  "patch": True,  "label": "standard analysis"},
    "high":   {"depth": 3, "budget_mult": 2.5, "correlate": True,  "patch": True,  "label": "deep forensic"},
}


class Modes:
    def __init__(self, cfg):
        self.mode = cfg["engine"]["mode"]
        if self.mode not in MODES:
            self.mode = "medium"

    def spec(self):
        return MODES[self.mode]

    def depth(self):
        return self.spec()["depth"]

    def budget_multiplier(self):
        return self.spec()["budget_mult"]

    def correlate_enabled(self):
        return self.spec()["correlate"]

    def patch_enabled(self):
        return self.spec()["patch"]

    def label(self):
        return self.spec()["label"]
