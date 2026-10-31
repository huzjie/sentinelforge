# Security

sentinelforge is a *reference implementation*, not a production scanner. Use it
to learn the architecture and as a starting point, not as your only line of
defense.

- It runs offline by design; if you extend it to fetch data, re-audit the
  sovereignty guarantees.
- The embedded CVE database is a tiny illustrative subset -- always pair with a
  full, up-to-date feed in production.
- Regex-based static analysis has known limits; combine with a real parser
  (AST-based SAST) for coverage.
