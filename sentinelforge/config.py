# -*- coding: utf-8 -*-
"""Runtime configuration with layered defaults (code default < recipe yaml < cli)."""
from __future__ import annotations

import copy

from .utils.yamlish import yaml_loads

# Defaults are deliberately small so a reference run stays interactive
# (<10s on a laptop) while still exercising every code path.
DEFAULTS = {
    "engine": {
        # low = fast triage, medium = standard analysis, high = deep forensic
        "mode": "medium",
        # hard ceiling on analysis tokens; pipeline degrades gracefully
        "token_budget": 4096,
        # sovereignty: never make network calls (always True for offline runs)
        "offline": True,
        # minimum model confidence to flag a candidate (0.0 - 1.0)
        "min_confidence": 0.5,
    },
    "detect": {
        "rules": [
            "sqli", "xss", "cmdi", "secrets", "pathtraversal",
            "weakcrypto", "ssrf", "deserialization", "openredirect",
        ],
        "include_cve": True,
        "include_ioc": True,
    },
    "analyze": {
        "severity_scale": "cvss",       # cvss-like 0.0 - 10.0 -> Critical..Info
        "correlate": True,
        "kill_chain": ["recon", "initial_access", "execution", "persistence", "exfiltration"],
    },
    "respond": {
        "generate_patch": True,
        "max_patch_lines": 12,
    },
    "model": {
        "skill": 0.5,                    # 0.0 (bad) .. 1.0 (expert); trainable
    },
    "report": {
        "format": "markdown",            # markdown | json | sarif
        "out_dir": "reports",
        "include_snippets": True,
    },
}


def _merge(base, override):
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(recipe_path=None):
    """Return the merged config dict. A recipe (yaml subset) overrides defaults."""
    cfg = copy.deepcopy(DEFAULTS)
    if recipe_path:
        with open(recipe_path, "r", encoding="utf-8") as f:
            raw = yaml_loads(f.read())
        cfg = _merge(cfg, raw)
    return cfg
