# -*- coding: utf-8 -*-
"""Remediation: turn findings into concrete, prioritized advice."""
from __future__ import annotations

PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def remediation_plan(triaged):
    """Return triaged findings sorted by severity priority, each with advice."""
    ordered = sorted(triaged, key=lambda t: PRIORITY.get(t.severity, 9))
    plan = []
    for t in ordered:
        plan.append({
            "priority": PRIORITY.get(t.severity, 9),
            "severity": t.severity,
            "rule_id": t.rule_id,
            "line": t.line,
            "advice": t.remediation,
            "snippet": t.snippet,
        })
    return plan


def remediation_quality(predicted_advice, gold_fix):
    """Token-overlap between predicted remediation and the gold fix.

    Deterministic and monotonic in the model skill that produced the advice:
    a stronger model emits advice closer to the gold fix.
    """
    if not gold_fix:
        return 1.0
    pred_tokens = set(predicted_advice.lower().split())
    gold_tokens = set(gold_fix.lower().split())
    if not gold_tokens:
        return 0.0
    return len(pred_tokens & gold_tokens) / len(gold_tokens)
