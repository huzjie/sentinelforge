# Remediation prompt template

```
For the finding below, produce:
1. A one-line explanation of the fix.
2. A minimal patch (unified diff) that removes the vulnerability.

<finding>
{rule_id}: {description}
snippet: {snippet}
</finding>

Prefer the smallest change that removes the issue; do not rewrite unrelated
logic.
```

## Reuse notes

- Ask for a *diff*, not prose, so the output is mechanically applicable.
- "Smallest change" keeps reviews cheap and reduces regressions.
