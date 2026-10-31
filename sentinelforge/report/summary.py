# -*- coding: utf-8 -*-
"""Summary metrics for a scan run."""
from __future__ import annotations


def summarize(triaged, chains, scan_results=None):
    """Return a flat dict of headline numbers."""
    by_sev = {}
    for t in triaged:
        by_sev[t.severity] = by_sev.get(t.severity, 0) + 1
    n_cve = sum(len(r.cves) for r in (scan_results or []))
    n_ioc = sum(len(r.iocs) for r in (scan_results or []))
    return {
        "findings": len(triaged),
        "critical": by_sev.get("critical", 0),
        "high": by_sev.get("high", 0),
        "medium": by_sev.get("medium", 0),
        "low": by_sev.get("low", 0),
        "info": by_sev.get("info", 0),
        "cves": n_cve,
        "iocs": n_ioc,
        "kill_chain_stages": len([s for s, fs in chains if fs]),
        "risk_score": _risk(triaged),
    }


def _risk(triaged):
    if not triaged:
        return 0
    return round(min(100.0, sum(t.score for t in triaged) / len(triaged) * 10), 1)
