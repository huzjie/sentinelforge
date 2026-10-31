# Contributing

1. Fork, clone, and create a branch.
2. Add tests under `tests/` for any new rule or metric.
3. Keep everything stdlib (no third-party imports in `sentinelforge/`).
4. Run `python -m unittest discover -s tests -t .` and
   `python -m sentinelforge doctor` before committing.

Security disclosures: report responsibly; do not file public issues for
unreleased vulnerabilities.
