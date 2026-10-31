# Architecture

sentinelforge is a six-stage pipeline. Everything is pure Python stdlib.

```
              +-------------+
   source --->|   detect    |  static rules + CVE manifest + IoC extract
              +-------------+
                    |
                    v
              +-------------+
              |    model    |  skill-parametrized confidence (filter)
              +-------------+
                    |
                    v
              +-------------+
              |   triage    |  CVSS-like severity + confidence
              +-------------+
                    |
                    v
              +-------------+
              |  correlate  |  kill-chain grouping (recon -> exfiltration)
              +-------------+
                    |
                    v
              +-------------+
              |   respond   |  remediation plan + patch generation
              +-------------+
                    |
                    v
              +-------------+
              |   report    |  markdown / json / sarif
              +-------------+
```

## Package layout

| Path | Responsibility |
|---|---|
| `detect/` | rules, scanner, CVE matcher, IoC extractor, fingerprint |
| `analyze/` | severity, confidence, triage, kill-chain correlation |
| `respond/` | remediation plan, patch generation |
| `report/` | markdown / json / sarif exporters + summary |
| `core/` | engine orchestration, model, reasoning modes, token budget, sovereignty |
| `world/` | ground-truth corpus + oracle (benchmark / training) |
| `training/` | monotonic skill trainer |

## Why zero dependencies

The whole point of a *sovereign* defender is that it runs inside your
perimeter with no supply-chain surface of its own. A pure-stdlib implementation
means: nothing to `pip install`, no transitive CVEs, and it runs anywhere
Python 3.9+ runs. The trade-off (no numpy/torch) is acceptable because this is
a *reference implementation* of the architecture, not a production scanner.
