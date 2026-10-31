# -*- coding: utf-8 -*-
"""Report generation: markdown / json exports."""
from __future__ import annotations

import json
from pathlib import Path


class Reporter:
    def __init__(self, cfg):
        self.cfg = cfg

    def render_markdown(self, summary, chains, triaged, scan_results=None):
        lines = []
        lines.append("# Sentinelforge Security Report")
        lines.append("")
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|---|---|")
        for k, v in summary.items():
            lines.append("| %s | %s |" % (k, v))
        lines.append("")
        lines.append("## Attack Chain")
        lines.append("")
        for stage, findings in chains:
            lines.append("### %s (%d finding(s))" % (stage, len(findings)))
            for t in findings:
                lines.append("- **[%s]** `%s` line %s (conf %.2f): %s"
                             % (t.severity.upper(), t.rule_id, t.line,
                                t.confidence, t.description))
        lines.append("")
        if triaged:
            lines.append("## Findings")
            lines.append("")
            lines.append("| Severity | Rule | Line | Snippet | Remediation |")
            lines.append("|---|---|---|---|---|")
            for t in sorted(triaged, key=lambda x: -x.score):
                lines.append("| %s | %s | %s | `%s` | %s |"
                             % (t.severity, t.rule_id, t.line,
                                (t.snippet or "")[:40], t.remediation[:80]))
            lines.append("")
        return "\n".join(lines)

    def render_json(self, summary, chains, triaged, scan_results=None):
        return json.dumps({
            "summary": summary,
            "chains": [(s, [t.to_dict() for t in fs]) for s, fs in chains],
            "findings": [t.to_dict() for t in triaged],
            "scans": [r.to_dict() for r in (scan_results or [])],
        }, ensure_ascii=False, indent=2)

    def write(self, content, out_dir="reports", name="report"):
        d = Path(out_dir)
        d.mkdir(parents=True, exist_ok=True)
        fmt = self.cfg["report"]["format"]
        ext = {"markdown": "md", "json": "json", "sarif": "sarif"}.get(fmt, "md")
        p = d / ("%s.%s" % (name, ext))
        p.write_text(content, encoding="utf-8")
        return str(p)
