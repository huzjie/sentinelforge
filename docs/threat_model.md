# Threat Model

sentinelforge targets the **source-code and dependency surface** of an
application, before and at the point of review. It is a static-analysis and
manifest-audit engine, not a runtime IDS.

## What it detects

1. **Injection classes** -- SQLi, command injection, XSS, SSRF, open redirect.
2. **Secret leakage** -- hardcoded credentials/tokens/keys in source.
3. **Weak cryptography** -- MD5/SHA-1 for security-sensitive hashing.
4. **Insecure deserialization** -- pickle / Java native deserialization.
5. **Path traversal** -- unguarded user path under a root dir.
6. **Known CVEs** -- vulnerable versions of popular dependencies.
7. **IoCs** -- hashes, public IPs, URLs, emails present in code.

## Kill chain

Findings are grouped into five stages: `recon` -> `initial_access` ->
`execution` -> `persistence` -> `exfiltration`. This grouping turns a flat list
of findings into a *narrative* an analyst can reason about.

## Out of scope

Runtime behavioral detection, network traffic inspection, binary analysis, and
zero-day discovery are all out of scope for this reference implementation.
