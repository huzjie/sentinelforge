# -*- coding: utf-8 -*-
"""Engine: orchestrates detect -> filter -> triage -> correlate -> respond -> report."""
from __future__ import annotations

from .model import Model
from .modes import Modes
from .token_budget import TokenBudget
from .sovereignty import Sovereignty
from ..analyze.triage import Triage
from ..analyze.correlate import KillChain
from ..analyze.severity import rule_base_score
from ..detect.scanner import Scanner
from ..respond.remediate import remediation_plan
from ..respond.patchgen import generate_patch
from ..report.reporter import Reporter
from ..report.sarif import to_sarif
from ..report.summary import summarize
from ..utils.rng import stable_float
from ..utils.text import snippet as _snippet


def _signal_for(finding):
    """Proxy evidence signal for a static finding (rule base score, 0-1)."""
    return rule_base_score(finding.rule_id) / 10.0


def _noise_for(path, finding):
    return stable_float("det:%s:%s:%d" % (path, finding.rule_id, finding.line))


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.model = Model(cfg["model"]["skill"])
        self.modes = Modes(cfg)
        self.budget = TokenBudget(cfg)
        self.sovereignty = Sovereignty(cfg["engine"]["offline"])
        self.triage = Triage(cfg)
        self.chain = KillChain(cfg["analyze"]["kill_chain"])
        self.scanner = Scanner(cfg)
        self.reporter = Reporter(cfg)

    def scan(self, path, text):
        """Run a full pipeline over one target and return a result dict."""
        self.sovereignty.assert_offline()
        min_conf = self.cfg["engine"]["min_confidence"]
        result = self.scanner.scan_text(path, text)

        flagged = []
        for f in result.findings:
            conf = self.model.confidence(_signal_for(f), _noise_for(path, f))
            if conf >= min_conf:
                flagged.append(self.triage.triage(f, conf))

        for cve in result.cves:
            flagged.append(self.triage.triage_cve(cve))

        chains = self.chain.correlate(flagged) if self.modes.correlate_enabled() else []
        plan = remediation_plan(flagged)
        summary = summarize(flagged, chains, [result])

        fmt = self.cfg["report"]["format"]
        if fmt == "json":
            content = self.reporter.render_json(summary, chains, flagged, [result])
        elif fmt == "sarif":
            content = to_sarif(flagged)
        else:
            content = self.reporter.render_markdown(summary, chains, flagged, [result])

        return {
            "summary": summary,
            "findings": [t.to_dict() for t in flagged],
            "chains": [(s, [t.to_dict() for t in fs]) for s, fs in chains],
            "plan": plan,
            "report": content,
            "mode": self.modes.label(),
            "token_used": self.budget.estimate(content),
            "sovereignty": self.sovereignty.audit(),
        }
