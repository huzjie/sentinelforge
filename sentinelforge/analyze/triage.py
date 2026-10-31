# -*- coding: utf-8 -*-
"""Triage: assign a final severity + confidence to each flagged finding."""
from __future__ import annotations

from .severity import cvss_score, score_to_label, rule_base_score
from .confidence import aggregate


class TriagedFinding:
    __slots__ = ("rule_id", "severity", "score", "confidence", "line", "snippet",
                 "description", "remediation", "is_true")

    def __init__(self, rule_id, severity, score, confidence, line, snippet,
                 description, remediation, is_true=None):
        self.rule_id = rule_id
        self.severity = severity
        self.score = score
        self.confidence = confidence
        self.line = line
        self.snippet = snippet
        self.description = description
        self.remediation = remediation
        self.is_true = is_true

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "score": round(self.score, 2),
            "confidence": round(self.confidence, 3),
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
        }


class Triage:
    def __init__(self, cfg):
        self.mode = cfg["engine"]["mode"]

    def triage(self, finding, confidence, is_true=None):
        score = cvss_score(finding.rule_id, confidence)
        label = score_to_label(score)
        return TriagedFinding(
            finding.rule_id, label, score, confidence, finding.line,
            finding.snippet, finding.description, finding.remediation, is_true,
        )

    def triage_cve(self, cve_hit):
        """CVE hits get a fixed base score blended with high confidence."""
        from .severity import severity_to_score, score_to_label
        base = severity_to_score(cve_hit["severity"])
        conf = aggregate(0.9, 0.9, self.mode)
        return TriagedFinding(
            "cve:" + cve_hit["cve"], score_to_label(base), base, conf,
            0, cve_hit["package"] + "@" + cve_hit["version"], cve_hit["desc"],
            "Upgrade to a fixed version and apply vendor guidance.", None,
        )

    def severity_accuracy(self, triaged, gold_severity):
        """Whether a triaged finding's label matches the gold severity."""
        return 1.0 if triaged.severity == gold_severity else 0.0
