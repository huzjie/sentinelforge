# Reasoning Modes (low / medium / high)

Mistral Large 4 exposes three inference modes -- low, medium, high -- so teams
can match *reasoning depth to the task* **without rewriting the prompt**. This
is the single most transferable idea in the release, and sentinelforge models
it directly.

## The insight

Adjusting effort by changing the prompt is fragile: the model's behavior
drifts, and you end up maintaining three prompts. Adjusting effort by changing a
*budget parameter* is stable: the signal (prompt + code) is identical, only the
compute/attention budget moves.

## How it maps here

| Mode | Depth | Budget | Correlation | Patch | Use case |
|---|---|---|---|---|---|
| `low` | 1 | 0.4x | no | no | fast CI triage |
| `medium` | 2 | 1.0x | yes | yes | standard review |
| `high` | 3 | 2.5x | yes | yes | deep forensic audit |

- **low** = detect + triage only. Fast, cheap, great for a pre-commit hook.
- **medium** = add kill-chain correlation + remediation patches.
- **high** = deepest analysis; same detection but maximum confidence refinement
  and full remediation, for an incident response or compliance audit.

## Reuse checklist

1. Keep the *signal* constant; vary a scalar *effort budget*.
2. Make each mode's behavior additive (low is a strict subset of high).
3. Expose the mode at the API boundary (`GET /v1/modes`) so callers can
   self-select rather than hard-coding.
