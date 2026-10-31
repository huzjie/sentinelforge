# -*- coding: utf-8 -*-
"""Attack-chain correlation: group findings into kill-chain stages."""
from __future__ import annotations

# rule_id -> kill-chain stage
STAGE_MAP = {
    "secrets": "initial_access",
    "openredirect": "recon",
    "ssrf": "recon",
    "sqli": "execution",
    "cmdi": "execution",
    "deserialization": "execution",
    "xss": "execution",
    "pathtraversal": "exfiltration",
    "weakcrypto": "persistence",
    "ioc": "recon",
}


class KillChain:
    """Build a coarse attack chain from a flat list of triaged findings."""

    ORDER = ["recon", "initial_access", "execution", "persistence", "exfiltration"]

    def __init__(self, stages=None):
        self.order = stages or self.ORDER

    def stage_of(self, rule_id):
        return STAGE_MAP.get(rule_id.split(":")[0], "execution")

    def correlate(self, triaged):
        """Return an ordered list of (stage, [findings...])."""
        buckets = {s: [] for s in self.order}
        for t in triaged:
            stage = self.stage_of(t.rule_id)
            if stage not in buckets:
                stage = "execution"
            buckets[stage].append(t)
        return [(s, buckets[s]) for s in self.order if buckets[s]]

    def risk_score(self, triaged):
        """Aggregate a whole-corpus risk score (0-100) from severity weights."""
        if not triaged:
            return 0.0
        total = sum(t.score for t in triaged)
        n = len(triaged)
        return round(min(100.0, (total / n) * (1.0 + 0.2 * (n - 1))), 1)
