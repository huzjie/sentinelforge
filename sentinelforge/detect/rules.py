# -*- coding: utf-8 -*-
"""Rule engine: compile and apply detection rules to source text."""
from __future__ import annotations

from .patterns import RULES, enabled_rule_ids


class Finding:
    """A single static-analysis hit with stable, ordered fields."""

    __slots__ = ("rule_id", "severity", "line", "snippet", "description", "remediation")

    def __init__(self, rule_id, severity, line, snippet, description, remediation):
        self.rule_id = rule_id
        self.severity = severity
        self.line = line
        self.snippet = snippet
        self.description = description
        self.remediation = remediation

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "remediation": self.remediation,
        }


class RuleEngine:
    """Apply regex rules line-by-line; a rule matches a line if ANY pattern hits."""

    def __init__(self, enabled=None):
        self.rules = enabled_rule_ids(enabled)

    def scan(self, text):
        findings = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, 1):
            for rule_id, severity, description, remediation, patterns in self.rules:
                if any(p.search(line) for p in patterns):
                    findings.append(Finding(
                        rule_id, severity, idx, line.strip(),
                        description, remediation,
                    ))
        return findings
