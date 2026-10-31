# -*- coding: utf-8 -*-
"""Hard token budget with graceful degradation (Mistral's 47%-fewer-token goal)."""
from __future__ import annotations

from ..utils.text import estimate_tokens


class TokenBudget:
    def __init__(self, cfg):
        self.limit = cfg["engine"]["token_budget"]

    def estimate(self, text):
        return estimate_tokens(text)

    def compress(self, text, limit=None):
        """Truncate + summarize long content to fit under the budget."""
        cap = limit or self.limit
        if self.estimate(text) <= cap:
            return text, False
        # keep a leading window + a trailing note
        keep = max(1, cap)
        head = text[: keep * 4]
        return head + "\n...[truncated by token budget]...", True

    def remaining(self, used):
        return max(0, self.limit - used)
