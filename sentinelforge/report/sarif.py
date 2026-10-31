# -*- coding: utf-8 -*-
"""SARIF 2.1.0 export (Static Analysis Results Interchange Format)."""
from __future__ import annotations

import json

RULES = {
    "sqli": "SENTINEL/sqli",
    "xss": "SENTINEL/xss",
    "cmdi": "SENTINEL/cmdi",
    "secrets": "SENTINEL/secrets",
    "pathtraversal": "SENTINEL/pathtraversal",
    "weakcrypto": "SENTINEL/weakcrypto",
    "ssrf": "SENTINEL/ssrf",
    "deserialization": "SENTINEL/deserialization",
    "openredirect": "SENTINEL/openredirect",
}


def _level(severity):
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(severity, "warning")


def to_sarif(triaged):
    rules = []
    seen = set()
    for t in triaged:
        rid = RULES.get(t.rule_id, "SENTINEL/" + t.rule_id)
        if rid not in seen:
            seen.add(rid)
            rules.append({
                "id": rid,
                "shortDescription": {"text": t.rule_id},
                "properties": {"severity": t.severity},
            })
    results = []
    for t in triaged:
        results.append({
            "ruleId": RULES.get(t.rule_id, "SENTINEL/" + t.rule_id),
            "level": _level(t.severity),
            "message": {"text": t.description},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "scan-target"},
                "region": {"startLine": t.line if t.line else 1},
            }}],
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "sentinelforge", "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)
