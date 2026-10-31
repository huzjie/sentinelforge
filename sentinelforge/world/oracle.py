# -*- coding: utf-8 -*-
"""Oracle: maps scanner candidates to ground truth, exposes train/bench signals.

The oracle is what makes the skill-parametrized model trainable and the bench
reproducible: it knows, for every candidate, whether it is a true positive and
how strongly the evidence supports it. The model blends that *oracle signal*
with noise proportionally to its skill -- a proxy for a real model that gets
better at extracting the true signal as it is trained.
"""
from __future__ import annotations

from ..utils.rng import stable_float
from .corpus import make_samples

TRUE_SIGNAL = 0.90      # strong evidence for a real finding
FALSE_SIGNAL = 0.10     # weak (distractor) evidence


def _flatten():
    samples = make_samples()
    cands = []
    for s in samples:
        for i, f in enumerate(s["findings"]):
            key = "%s:%s:%d" % (s["id"], f["type"], i)
            cands.append({
                "id": key,
                "sample_id": s["id"],
                "type": f["type"],
                "is_true": True,
                "signal": TRUE_SIGNAL,
                "noise": stable_float("noise:" + key),
                "severity": f["severity"],
                "description": f["description"],
            })
        for j, b in enumerate(s.get("benign", [])):
            key = "%s:benign:%d" % (s["id"], j)
            cands.append({
                "id": key,
                "sample_id": s["id"],
                "type": "benign",
                "is_true": False,
                "signal": FALSE_SIGNAL,
                "noise": stable_float("noise:" + key),
                "severity": "info",
                "description": "benign line (distractor)",
            })
    return cands


def make_batch():
    """Return the full candidate list (true + benign distractors)."""
    return _flatten()


def true_count(batch):
    return sum(1 for c in batch if c["is_true"])


def false_count(batch):
    return sum(1 for c in batch if not c["is_true"])
