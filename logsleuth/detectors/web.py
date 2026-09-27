"""Web access-log detectors: scanning, injection attempts, sensitive paths."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import List, Sequence
from urllib.parse import unquote

from ..models import Alert, Event, EventKind, MitreTechnique, Severity
from .base import BaseDetector, time_span

# Signatures for common web exploitation attempts (checked case-insensitively).
_ATTACK_SIGNATURES = [
    ("SQL injection", re.compile(r"(union\s+select|\bor\s+1\s*=\s*1\b|';|\bsleep\s*\(|information_schema)", re.I)),
    ("Cross-site scripting", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|%3cscript)", re.I)),
    ("Path traversal / LFI", re.compile(r"(\.\./|\.\.%2f|/etc/passwd|boot\.ini|%2e%2e%2f)", re.I)),
    ("Command injection", re.compile(r"(;\s*cat\s|\|\s*id\b|`.*`|\$\(.*\)|/bin/sh)", re.I)),
]

# Paths that are almost always recon / opportunistic probing.
_SENSITIVE_PATHS = re.compile(
    r"(/\.env|/\.git|/wp-login\.php|/wp-admin|/phpmyadmin|/\.aws|/config\.php|/admin\b|/\.ssh)",
    re.I,
)


class WebAttackDetector(BaseDetector):
    """Injection / exploitation signatures in request paths."""

    name = "web_attack"

    def run(self, events: Sequence[Event]) -> List[Alert]:
        hits = defaultdict(list)  # (ip, attack_name) -> events
        for e in events:
            if e.kind is not EventKind.HTTP_REQUEST or not e.path:
                continue
            decoded = unquote(e.path)
            for attack_name, pattern in _ATTACK_SIGNATURES:
                if pattern.search(decoded) or pattern.search(e.path):
                    hits[(e.source_ip, attack_name)].append(e)
                    break

        alerts: List[Alert] = []
        for (ip, attack_name), evs in hits.items():
            first, last = time_span(evs)
            alerts.append(Alert(
                detector=self.name,
                title=f"Web attack: {attack_name}",
                severity=Severity.HIGH,
                source_ip=ip,
                mitre=MitreTechnique("T1190", "Exploit Public-Facing Application"),
                description=f"{len(evs)} request(s) from {ip} matched {attack_name} signatures.",
                count=len(evs),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in evs[:3]],
            ))
        return alerts


class WebScanningDetector(BaseDetector):
    """Many 404s from one source = directory / content scanning."""

    name = "web_scanning"

    def __init__(self, threshold: int = 20):
        self.threshold = threshold

    def run(self, events: Sequence[Event]) -> List[Alert]:
        not_found = defaultdict(list)
        for e in events:
            if e.kind is EventKind.HTTP_REQUEST and e.status == 404:
                not_found[e.source_ip].append(e)

        alerts: List[Alert] = []
        for ip, evs in not_found.items():
            if len(evs) < self.threshold:
                continue
            first, last = time_span(evs)
            alerts.append(Alert(
                detector=self.name,
                title="Web content scanning (excessive 404s)",
                severity=Severity.MEDIUM,
                source_ip=ip,
                mitre=MitreTechnique("T1595.003", "Active Scanning: Wordlist Scanning"),
                description=f"{ip} generated {len(evs)} HTTP 404s — likely directory brute-forcing.",
                count=len(evs),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in evs[:3]],
            ))
        return alerts


class SensitivePathDetector(BaseDetector):
    """Access attempts to sensitive files/paths (.env, .git, admin panels)."""

    name = "web_sensitive_path"

    def run(self, events: Sequence[Event]) -> List[Alert]:
        hits = defaultdict(list)
        for e in events:
            if e.kind is EventKind.HTTP_REQUEST and e.path and _SENSITIVE_PATHS.search(e.path):
                hits[e.source_ip].append(e)

        alerts: List[Alert] = []
        for ip, evs in hits.items():
            first, last = time_span(evs)
            paths = sorted({e.path for e in evs})
            alerts.append(Alert(
                detector=self.name,
                title="Sensitive path access attempt",
                severity=Severity.MEDIUM,
                source_ip=ip,
                mitre=MitreTechnique("T1083", "File and Directory Discovery"),
                description=f"{ip} probed sensitive path(s): {', '.join(paths[:5])}.",
                count=len(evs),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in evs[:3]],
            ))
        return alerts
