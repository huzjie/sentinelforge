# Sovereignty: offline by design

The core promise of an open-weight, self-hostable defender is that your code
and data never leave your perimeter. sentinelforge enforces this structurally.

## Guarantees

- **No network calls anywhere** in the pipeline (grep for `http` in `core/` and
  `detect/` -- there are none in the execution path).
- **`Sovereignty.assert_offline()`** is called at the top of every scan; if
  `engine.offline` is false it raises, so online operation must be an explicit,
  auditable decision.
- **Audit trail**: every result carries a `sovereignty` block
  (`network_egress: 0`, `data_residency: local`, `third_party_calls: 0`).

## Why this matters for defenders

A security vendor's scanner that uploads your code to their cloud is itself a
supply-chain and exfiltration risk. An open-weight model you can run locally
(`Le Chonk` being the canonical recent example) removes that dependency. The
same logic applies to the *tooling*: it should be as self-contained as the
model it wraps.
