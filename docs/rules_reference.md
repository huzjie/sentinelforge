# Detection Rules Reference

Each rule maps to a regex pattern (see `detect/patterns.py`) plus a base
severity and remediation guidance. Patterns are intentionally focused on the
classic, unambiguous anti-patterns.

| Rule | Severity | What it catches |
|---|---|---|
| `sqli` | critical | SQL built by `+`/f-string/`.format` interpolation |
| `cmdi` | critical | `os.system`, `subprocess(..., shell=True)`, `eval`, `exec(... + ...)` |
| `deserialization` | critical | `pickle.loads`, Java `ObjectInputStream` |
| `secrets` | critical | hardcoded api_key/token/password literals, `ghp_`, `sk-`, `AKIA`, PEM headers |
| `xss` | high | `innerHTML`, `document.write`, `.html()` |
| `ssrf` | high | `requests.get(url)`, `urlopen(url)` |
| `pathtraversal` | high | `os.path.join(base, user)`, `open(... + ...)`, `"../"` |
| `weakcrypto` | high | `hashlib.md5`, `hashlib.sha1` |
| `openredirect` | medium | `redirect(request.args.get(...))` |

## Adding a rule

1. Add a `(rule_id, severity, description, remediation, [patterns])` tuple to
   `RULES` in `detect/patterns.py`.
2. (Optional) map the rule to a kill-chain stage in `analyze/correlate.py`.
3. Add its base score to `RULE_BASE` in `analyze/severity.py`.

Patterns are written *backslash-free* (`[.]` for dot, `[+]` for plus, `[0-9]`
for digit) so the generator can emit them verbatim with no escape ambiguity.
