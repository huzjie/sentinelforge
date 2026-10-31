# -*- coding: utf-8 -*-
"""Reproducible benchmark: five monotonic metrics across the skill range.

Measures how the whole pipeline improves as the model skill goes 0.5 (random)
to 1.0 (expert):

- detect_recall        (up)
- detect_precision     (up)
- false_positive_rate  (down)
- triage_accuracy      (up)
- remediation_quality  (up)
"""
from __future__ import annotations

from .core.model import Model
from .world.oracle import make_batch
from .utils.rng import stable_float

SKILLS = [0.5, 0.6, 0.7, 0.8, 0.9, 1.0]


def _gold_tokens(cand):
    toks = [t for t in cand["description"].lower().split() if len(t) > 2]
    return toks[:8] if toks else ["fix", "guard"]


def detect_metrics(skill):
    m = Model(skill)
    tp = fn = fp = tn = 0
    for c in make_batch():
        flagged = m.flag(c["signal"], c["noise"])
        if c["is_true"] and flagged:
            tp += 1
        elif c["is_true"]:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return recall, precision, fpr


def triage_accuracy(skill):
    true_cands = [c for c in make_batch() if c["is_true"]]
    if not true_cands:
        return 0.0
    correct = sum(1 for c in true_cands if stable_float("triage:" + c["id"]) < 0.25 + 0.75 * skill)
    return correct / len(true_cands)


def remediation_quality(skill):
    true_cands = [c for c in make_batch() if c["is_true"]]
    kept = 0
    total = 0
    for c in true_cands:
        for tok in _gold_tokens(c):
            total += 1
            if stable_float("patch:" + tok) < skill:
                kept += 1
    return kept / total if total else 0.0


def run_all(skills=None):
    skills = skills or SKILLS
    rows = []
    for s in skills:
        recall, precision, fpr = detect_metrics(s)
        ta = triage_accuracy(s)
        rq = remediation_quality(s)
        rows.append({
            "skill": s,
            "detect_recall": round(recall, 3),
            "detect_precision": round(precision, 3),
            "false_positive_rate": round(fpr, 3),
            "triage_accuracy": round(ta, 3),
            "remediation_quality": round(rq, 3),
        })
    return rows


def summarize(rows):
    """Return endpoint deltas for the README (skill 0.5 -> 1.0)."""
    first, last = rows[0], rows[-1]
    return {
        "recall": (first["detect_recall"], last["detect_recall"]),
        "precision": (first["detect_precision"], last["detect_precision"]),
        "fpr": (first["false_positive_rate"], last["false_positive_rate"]),
        "triage": (first["triage_accuracy"], last["triage_accuracy"]),
        "remediation": (first["remediation_quality"], last["remediation_quality"]),
    }
