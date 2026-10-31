# -*- coding: utf-8 -*-
"""sentinelforge: a sovereign autonomous cyber-defense engine.

Most security tooling today ships your code off to a third-party cloud. When
Mistral open-sourced the weights of Mistral Large 4 ("Le Chonk") -- a ~1T
parameter mixture-of-experts model explicitly tuned for cybersecurity -- the
core promise was *sovereignty*: run frontier threat detection, analysis and
remediation entirely inside your own perimeter, on your own data, with no
network egress.

sentinelforge is a self-contained, zero-dependency reference implementation of
that idea. It captures the three engineering pillars that make "Le Chonk"
notable for defenders:

1. **Threat detection** -- a static-analysis rule engine (SQLi / XSS / command
   injection / hardcoded secrets / path traversal / weak crypto / SSRF /
   insecure deserialization / open redirect), a CVE matcher for dependency
   manifests, and an IoC extractor for hashes / IPs / domains / URLs.
2. **Reasoning modes** -- three inference depths (low = fast triage, medium =
   standard analysis, high = deep forensic correlation) selected by a *budget*,
   not by rewriting your prompt. Same signal, variable effort.
3. **Sovereignty & token efficiency** -- fully offline, a hard token budget with
   graceful degradation, and no network calls anywhere in the pipeline.

The "model" here is a trainable, skill-parametrized scorer (deterministic,
seeded, monotonic in skill) so the whole detect -> triage -> correlate ->
respond loop is reproducible and can be validated end-to-end on a laptop in
seconds. Everything runs on the Python standard library.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
