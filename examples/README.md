# Examples

Two target directories for a quick end-to-end demo:

- `vulnerable/` -- intentionally insecure code (SQLi, command injection,
  hardcoded secrets, XSS, a vulnerable dependency manifest). Scanning it should
  surface multiple findings, a CVE, and IoCs.
- `safe/` -- the same functionality written defensively. Scanning it should
  surface (almost) nothing.

Run the scan:

    python -m sentinelforge scan examples/vulnerable
    python -m sentinelforge scan examples/safe
