# -*- coding: utf-8 -*-
"""Text helpers: normalization, snippet extraction, token estimation."""
from __future__ import annotations


def line_numbers(text: str):
    """Yield (1-based line number, line content) pairs."""
    for i, ln in enumerate(text.splitlines(), 1):
        yield i, ln


def snippet(text: str, lineno: int, width: int = 1) -> str:
    """Return a few lines around a 1-based line number for display."""
    lines = text.splitlines()
    if not lines:
        return ""
    lo = max(0, lineno - 1 - width)
    hi = min(len(lines), lineno + width)
    return "\n".join(lines[lo:hi])


def estimate_tokens(text: str) -> int:
    """Rough token count (chars / 4) -- deterministic and dependency-free."""
    return max(1, len(text) // 4)


def normalize(s: str) -> str:
    return " ".join(s.split())
