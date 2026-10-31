# -*- coding: utf-8 -*-
"""Indicator-of-Compromise extraction: IPs, URLs, domains, emails, hashes."""
from __future__ import annotations

import re

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
URL = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)
DOMAIN = re.compile(r"\b[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?))+\b", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
SHA1 = re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

# Reserved / benign networks to skip when flagging IPs (crude private-range note)
PRIVATE = re.compile(r"^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)")


class Ioc:
    def __init__(self, kind, value, line):
        self.kind = kind
        self.value = value
        self.line = line

    def to_dict(self):
        return {"kind": self.kind, "value": self.value, "line": self.line}


class IocExtractor:
    def extract(self, path, text):
        iocs = []
        for idx, line in enumerate(text.splitlines(), 1):
            for m in URL.finditer(line):
                iocs.append(Ioc("url", m.group(0), idx))
            for m in MD5.finditer(line):
                iocs.append(Ioc("md5", m.group(0), idx))
            for m in SHA256.finditer(line):
                iocs.append(Ioc("sha256", m.group(0), idx))
            for m in SHA1.finditer(line):
                iocs.append(Ioc("sha1", m.group(0), idx))
            for m in EMAIL.finditer(line):
                iocs.append(Ioc("email", m.group(0), idx))
            for m in IPV4.finditer(line):
                ip = m.group(0)
                if not PRIVATE.match(ip):
                    iocs.append(Ioc("ip", ip, idx))
        return iocs
