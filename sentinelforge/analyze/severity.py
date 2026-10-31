# -*- coding: utf-8 -*-
"""CVSS-like severity scoring (0.0 - 10.0 -> Critical..Info)."""
from __future__ import annotations

from ..utils.linalg import clamp

# base severity weight per rule (subjective but documented and tunable)
RULE_BASE = {
    "sqli": 9.0,
    "cmdi": 9.5,
    "deserialization": 9.0,
    "secrets": 8.5,
    "xss": 7.0,
    "ssrf": 7.5,
    "pathtraversal": 6.5,
    "weakcrypto": 5.5,
    "openredirect": 4.5,
    "benign": 0.0,
}

CVE_BASE = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.5,
}


def severity_to_score(severity):
    return CVE_BASE.get(severity, 5.0)


def score_to_label(score):
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"


def rule_base_score(rule_id):
    return RULE_BASE.get(rule_id, 5.0)


def cvss_score(rule_id, confidence):
    """Combine a rule's base score with detection confidence.

    A high-confidence hit keeps its base; a shaky hit is discounted.
    """
    base = rule_base_score(rule_id)
    return clamp(base * (0.5 + 0.5 * confidence), 0.0, 10.0)
