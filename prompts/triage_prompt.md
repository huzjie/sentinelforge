# Triage prompt template

```
Given these findings, assign each a severity (critical/high/medium/low/info)
and a confidence (0.0-1.0).

<findings>
{findings_json}
</findings>

Consider: reachability (is the sink exploitable?), attacker control (is input
untrusted?), and blast radius (what happens on success). A hardcoded secret in
a public repo is critical; an open redirect to an internal path is low.
```

## Reuse notes

- Triage is a *second stage*: it never invents findings, only re-ranks them.
- Expose the three dimensions (reachability / control / blast radius) so the
  model's reasoning is auditable.
