# -*- coding: utf-8 -*-
"""Small embedded CVE database + dependency-manifest matching (version compare)."""
from __future__ import annotations

import re

# A deliberately small, well-known subset. Each entry: id, package(s), a
# vulnerable-version bound, fixed version hint, severity, description.
# Bound is expressed via "below" (vulnerable if ver < below) or "range"
# (lo, hi) inclusive (vulnerable if lo <= ver <= hi).
CVE_DB = [
    {"id": "CVE-2021-44228", "packages": ["log4j-core", "log4j", "org.apache.logging.log4j"],
     "below": "2.15.0", "fixed": "2.15.0", "severity": "critical",
     "desc": "Log4Shell: JNDI lookup RCE in Log4j2."},
    {"id": "CVE-2023-4863", "packages": ["libwebp", "webp"],
     "below": "1.3.2", "fixed": "1.3.2", "severity": "critical",
     "desc": "Heap buffer overflow in libwebp (WebP) decoding."},
    {"id": "CVE-2024-3094", "packages": ["xz", "liblzma", "xz-utils"],
     "range": ("5.6.0", "5.6.1"), "fixed": "5.6.2", "severity": "critical",
     "desc": "Backdoor injected into xz/liblzma tarballs."},
    {"id": "CVE-2017-5638", "packages": ["struts2-core", "struts"],
     "below": "2.5.11", "fixed": "2.5.11", "severity": "critical",
     "desc": "Apache Struts2 Jakarta multipart parser RCE."},
    {"id": "CVE-2017-0144", "packages": ["samba", "samba-common"],
     "below": "4.5.7", "fixed": "4.5.7", "severity": "critical",
     "desc": "EternalBlue: SMBv1 remote code execution (MS17-010)."},
    {"id": "CVE-2021-41773", "packages": ["apache2", "httpd"],
     "below": "2.4.50", "fixed": "2.4.50", "severity": "high",
     "desc": "Apache httpd path traversal / RCE in 2.4.49."},
    {"id": "CVE-2019-11043", "packages": ["php", "php-fpm"],
     "below": "7.3.11", "fixed": "7.3.11", "severity": "high",
     "desc": "PHP-FPM env_path_info underflow RCE (nginx)."},
    {"id": "CVE-2018-1000861", "packages": ["jenkins", "jenkins-core"],
     "below": "2.154", "fixed": "2.154", "severity": "high",
     "desc": "Jenkins Stapler web framework deserialization RCE."},
]


def _parse_version(v):
    """Normalize a version string to a comparable tuple of ints."""
    m = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v))
    if not m:
        return (0, 0, 0)
    return tuple(int(x or 0) for x in m.groups())


def version_lt(a, b):
    return _parse_version(a) < _parse_version(b)


def version_le(a, b):
    return _parse_version(a) <= _parse_version(b)


class CveMatcher:
    """Parse common manifests and report known-vulnerable dependencies."""

    MANIFEST = re.compile(
        r"(requirements\.txt|package\.json|Pipfile|pyproject\.toml|pom\.xml|build\.gradle)$",
        re.IGNORECASE)

    def is_manifest(self, path):
        return bool(self.MANIFEST.search(path))

    def match_manifest(self, path, text):
        """Return list of {cve, package, version, severity, desc} hits."""
        if not self.is_manifest(path):
            return []
        hits = []
        for name, ver in self._iter_deps(text):
            for cve in CVE_DB:
                if name.lower() not in [p.lower() for p in cve["packages"]]:
                    continue
                if "range" in cve:
                    lo, hi = cve["range"]
                    vuln = version_le(lo, ver) and version_le(ver, hi)
                else:
                    vuln = version_lt(ver, cve["below"])
                if vuln:
                    hits.append({"cve": cve["id"], "package": name, "version": ver,
                                 "severity": cve["severity"], "desc": cve["desc"]})
        return hits

    @staticmethod
    def _iter_deps(text):
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][A-Za-z0-9.\-]*)", line)
            if m:
                out.append((m.group(1), m.group(2)))
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)\s*([<>=~!]+)\s*([0-9][A-Za-z0-9.\-]*)", line)
            if m:
                out.append((m.group(1), m.group(3)))
        return out
