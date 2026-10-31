# -*- coding: utf-8 -*-
"""Deterministic content fingerprinting (sha256) for change tracking."""
from __future__ import annotations

import hashlib


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_fingerprint(text):
    """Return a short stable fingerprint (first 16 hex of sha256)."""
    return sha256(text)[:16]
