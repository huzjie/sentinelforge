# Token Budget & Efficiency

Mistral advertises ML4 as using ~47% fewer tokens than GLM-5.3 for comparable
work. For a security scanner, token efficiency isn't a cost nicety -- it is the
difference between a scan that fits in a CI budget and one that doesn't.

## Implementation

- `TokenBudget.estimate()` uses a deterministic `chars/4` heuristic (stdlib, no
  tokenizer dependency).
- `TokenBudget.compress()` truncates long snippets to a leading window plus a
  marker, so reports degrade gracefully instead of failing.
- The reasoning mode scales the *effective* budget (`low` = 0.4x, `high` = 2.5x)
  so the same hard ceiling produces different depths.

## Reuse checklist

1. Set a hard budget up front and degrade gracefully -- never let a long input
   blow up a pipeline.
2. Budget should be a *parameter*, orthogonal to the prompt.
3. Summarize/truncate deterministically so results are reproducible.
