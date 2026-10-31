# -*- coding: utf-8 -*-
"""Confidence aggregation: model confidence + evidence strength + mode depth."""
from __future__ import annotations

from ..utils.linalg import clamp

# How much each reasoning mode trusts the model's confidence signal.
MODE_GAIN = {"low": 0.6, "medium": 1.0, "high": 1.3}


def aggregate(model_conf, evidence=0.5, mode="medium"):
    """Blend model confidence with static evidence, scaled by reasoning depth."""
    gain = MODE_GAIN.get(mode, 1.0)
    raw = model_conf * 0.7 + evidence * 0.3
    return clamp(raw * gain)
