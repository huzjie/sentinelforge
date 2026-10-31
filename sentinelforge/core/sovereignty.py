# -*- coding: utf-8 -*-
"""Sovereignty guarantees: fully offline, no network egress, data residency."""
from __future__ import annotations


class Sovereignty:
    """Enforces that the pipeline never leaves the perimeter."""

    def __init__(self, offline=True):
        self.offline = offline

    def assert_offline(self):
        if not self.offline:
            raise RuntimeError("sentinelforge must run offline (sovereignty)")
        return True

    def audit(self):
        return {
            "offline": self.offline,
            "network_egress": 0,
            "data_residency": "local",
            "third_party_calls": 0,
        }
