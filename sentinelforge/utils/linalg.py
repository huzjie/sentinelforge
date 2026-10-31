# -*- coding: utf-8 -*-
"""Tiny linear-algebra helpers for severity / confidence aggregation (no numpy)."""
from __future__ import annotations


def dot(a, b):
    return sum(x * y for x, y in zip(a, b))


def weighted_average(values, weights):
    total = sum(weights)
    if total == 0:
        return 0.0
    return sum(v * w for v, w in zip(values, weights)) / total


def clamp(x, lo=0.0, hi=1.0):
    return max(lo, min(hi, x))
