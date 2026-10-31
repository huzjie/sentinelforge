# -*- coding: utf-8 -*-
"""Patch generation: emit a minimal unified-diff style fix for a finding."""
from __future__ import annotations

from ..utils.rng import stable_float


def _merge_tokens(advice, gold_fix, skill):
    """Deterministically decide which gold tokens survive, driven by skill.

    This mirrors how a stronger model reproduces the gold fix more faithfully:
    each gold token is kept iff a seeded value is below the skill threshold.
    """
    kept = []
    for tok in gold_fix.split():
        if stable_float("patch:" + tok) < skill:
            kept.append(tok)
    return " ".join(kept)


def generate_patch(finding, gold_fix, skill, max_lines=12):
    """Return a (patch_text, quality) pair.

    At skill=1.0 the patch equals the gold fix (quality 1.0); at lower skill
    it is a noisier subset. Deterministic given the same finding + gold fix.
    """
    if not gold_fix:
        return "", 1.0
    patch = _merge_tokens(finding.rule_id, gold_fix, skill)
    quality = _quality(patch, gold_fix)
    lines = ["--- a/%s" % finding.rule_id, "+++ b/%s" % finding.rule_id]
    for ln in patch.split("\n")[:max_lines]:
        lines.append("+" + ln)
    return "\n".join(lines), quality


def _quality(patch, gold_fix):
    pt = set(patch.lower().split())
    gt = set(gold_fix.lower().split())
    if not gt:
        return 0.0
    return len(pt & gt) / len(gt)
