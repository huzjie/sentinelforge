# -*- coding: utf-8 -*-
"""Regular-expression patterns used by the static-analysis rule engine.

Patterns are intentionally focused (high precision) rather than exhaustive.
They catch the classic, unambiguous anti-patterns; a real deployment would
combine these with a language-specific parser. Each rule id maps to a list of
compiled patterns plus metadata (severity / description / remediation).
"""
from __future__ import annotations

import re

# (rule_id, severity, description, remediation, [patterns...])
# NOTE: patterns are deliberately backslash-free (use [.] [+] [0-9] etc.) so the
# generator can emit them verbatim without escape ambiguities.
RULES = [
    # --- SQL injection ------------------------------------------------------
    ("sqli", "critical",
     "SQL query built by string concatenation / interpolation with untrusted input",
     "Use parameterized queries (placeholders) instead of string concatenation",
     [
         re.compile("(SELECT|INSERT|UPDATE|DELETE|WHERE)[^']*'[ ]*[+]", re.IGNORECASE),
         re.compile('(SELECT|INSERT|UPDATE|DELETE|WHERE)[^"]*"[ ]*[+]', re.IGNORECASE),
         re.compile('f"(SELECT|INSERT|UPDATE|DELETE)', re.IGNORECASE),
     ]),
    # --- XSS ---------------------------------------------------------------
    ("xss", "high",
     "Untrusted input sunk into the DOM without escaping",
     "Use textContent / createElement or an HTML escaping function",
     [
         re.compile("[.]innerHTML[ ]*[+=-]"),
         re.compile("document[.]write[(]"),
         re.compile("[.]html[(][ ]*[A-Za-z_]+[ ]*[)]"),
     ]),
    # --- Command injection --------------------------------------------------
    ("cmdi", "critical",
     "Untrusted input passed to a shell / eval sink",
     "Avoid shell; use subprocess.run with an argument list (shell=False)",
     [
         re.compile("os[.]system[(]"),
         re.compile("subprocess[.](call|run|Popen)[(][^)]*shell[ ]*=[ ]*True", re.IGNORECASE),
         re.compile("eval[(]"),
         re.compile("exec[(][^)]*[+]"),
     ]),
    # --- Hardcoded secrets ---------------------------------------------------
    ("secrets", "critical",
     "Hardcoded credential / token / key literal in source",
     "Load secrets from environment or a secret manager; rotate exposed values",
     [
         re.compile("(api[_-]?key|secret|token|password|passwd)[ ]*=[ ]*'", re.IGNORECASE),
         re.compile('(api[_-]?key|secret|token|password|passwd)[ ]*=[ ]*"', re.IGNORECASE),
         re.compile("ghp_[A-Za-z0-9]{20,}"),
         re.compile("sk-[A-Za-z0-9]{20,}"),
         re.compile("AKIA[0-9A-Z]{16}"),
         re.compile("-----BEGIN[ A-Z]+PRIVATE KEY-----"),
     ]),
    # --- Path traversal ------------------------------------------------------
    ("pathtraversal", "high",
     "User-controlled path joined onto a root without traversal guard",
     "Resolve the real path and verify it stays within the allowed directory",
     [
         re.compile("os[.]path[.]join[(][ ]*[A-Za-z_]+[ ]*,[ ]*[A-Za-z_]+[ ]*[)]"),
         re.compile("open[(][^)]*[+]"),
         re.compile('["][/][^"]*["][ ]*[+]'),
         re.compile("[.]{2}/"),
     ]),
    # --- Weak cryptography ----------------------------------------------------
    ("weakcrypto", "high",
     "Fast / broken hash or cipher used for a security-sensitive purpose",
     "Use a slow salted KDF (scrypt/PBKDF2) or a modern AEAD cipher",
     [
         re.compile("hashlib[.]md5[(]"),
         re.compile("hashlib[.]sha1[(]"),
     ]),
    # --- SSRF ------------------------------------------------------------------
    ("ssrf", "high",
     "Server fetches an arbitrary user-supplied URL",
     "Allow-list schemes/hosts and block private IP ranges",
     [
         re.compile("requests[.](get|post|put)[(][ ]*[A-Za-z_]+[ ]*[)]"),
         re.compile("urlopen[(][ ]*[A-Za-z_]+[ ]*[)]"),
     ]),
    # --- Insecure deserialization ----------------------------------------------
    ("deserialization", "critical",
     "Untrusted data deserialized into objects (potential code execution)",
     "Use JSON/schema validation; never unpickle untrusted input",
     [
         re.compile("pickle[.]loads?[(]"),
         re.compile("ObjectInputStream"),
     ]),
    # --- Open redirect -----------------------------------------------------------
    ("openredirect", "medium",
     "Redirect target taken from user input without validation",
     "Validate the target against an allow-list of internal paths",
     [
         re.compile("redirect[(][ ]*request[.](args|GET|form)[.]get"),
     ]),
]


def rules_by_id():
    return {r[0]: r for r in RULES}


def enabled_rule_ids(enabled):
    """Return rule tuples restricted to the enabled id list (empty = all)."""
    if not enabled:
        return list(RULES)
    by_id = rules_by_id()
    return [by_id[i] for i in enabled if i in by_id]
