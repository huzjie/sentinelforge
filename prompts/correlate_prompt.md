# Correlation prompt template

```
Group the following findings into an attack chain using stages:
recon -> initial_access -> execution -> persistence -> exfiltration.

<findings>
{findings_json}
</findings>

A hardcoded secret is initial_access; SQLi/command injection is execution;
path traversal on sensitive files is exfiltration. A finding may map to one
stage. Return the chain as an ordered list.
```

## Reuse notes

- Correlation turns a flat list into a *story*, which is what an analyst
  actually reads.
- Fixing the earliest stage (e.g., the leaked secret) often collapses the whole
  chain -- call that out explicitly in the output.
