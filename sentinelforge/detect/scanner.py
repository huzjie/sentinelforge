# -*- coding: utf-8 -*-
"""Unified file scanner: static rules + CVE manifest check + IoC extraction."""
from __future__ import annotations

from .rules import RuleEngine
from .cve import CveMatcher
from .ioc import IocExtractor
from .fingerprint import file_fingerprint


class ScanResult:
    def __init__(self, path, findings, cves, iocs, fingerprint):
        self.path = path
        self.findings = findings
        self.cves = cves
        self.iocs = iocs
        self.fingerprint = fingerprint

    def to_dict(self):
        return {
            "path": self.path,
            "fingerprint": self.fingerprint,
            "findings": [f.to_dict() for f in self.findings],
            "cves": self.cves,
            "iocs": [i.to_dict() for i in self.iocs],
        }


class Scanner:
    """Scans a single source/manifest file and returns a ScanResult."""

    def __init__(self, cfg):
        self.engine = RuleEngine(cfg["detect"]["rules"])
        self.cve = CveMatcher()
        self.ioc = IocExtractor()

    def scan_text(self, path, text):
        findings = self.engine.scan(text)
        cves = self.cve.match_manifest(path, text)
        iocs = self.ioc.extract(path, text)
        fp = file_fingerprint(text)
        return ScanResult(path, findings, cves, iocs, fp)

    def scan_file(self, path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        return self.scan_text(str(path), text)
