"""SSH brute force + password spraying + successful compromise detectors."""

from __future__ import annotations

from collections import defaultdict
from typing import List, Sequence

from ..models import Alert, Event, EventKind, MitreTechnique, Severity
from .base import BaseDetector, time_span, within_window


def _by_ip(events, kinds):
    grouped = defaultdict(list)
    for e in events:
        if e.kind in kinds:
            grouped[e.source_ip].append(e)
    return grouped


class SSHBruteForceDetector(BaseDetector):
    """Many failed SSH logins from one source in a short window."""

    name = "ssh_bruteforce"

    def __init__(self, threshold: int = 10, window_seconds: int = 120):
        self.threshold = threshold
        self.window_seconds = window_seconds

    def run(self, events: Sequence[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        grouped = _by_ip(events, (EventKind.SSH_FAILED, EventKind.SSH_INVALID_USER))
        for ip, evs in grouped.items():
            if len(evs) < self.threshold:
                continue
            if not within_window(evs, self.threshold, self.window_seconds):
                continue
            first, last = time_span(evs)
            users = sorted({e.user for e in evs if e.user})
            alerts.append(Alert(
                detector=self.name,
                title="SSH brute-force attempt",
                severity=Severity.HIGH,
                source_ip=ip,
                mitre=MitreTechnique("T1110.001", "Brute Force: Password Guessing"),
                description=f"{len(evs)} failed SSH logins from {ip} "
                            f"targeting {len(users)} user(s).",
                count=len(evs),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in evs[:3]],
            ))
        return alerts


class SSHPasswordSprayDetector(BaseDetector):
    """One source trying many distinct usernames (spray / enumeration)."""

    name = "ssh_password_spray"

    def __init__(self, min_users: int = 8):
        self.min_users = min_users

    def run(self, events: Sequence[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        grouped = _by_ip(events, (EventKind.SSH_FAILED, EventKind.SSH_INVALID_USER))
        for ip, evs in grouped.items():
            users = sorted({e.user for e in evs if e.user})
            if len(users) < self.min_users:
                continue
            first, last = time_span(evs)
            alerts.append(Alert(
                detector=self.name,
                title="SSH password spraying / user enumeration",
                severity=Severity.MEDIUM,
                source_ip=ip,
                mitre=MitreTechnique("T1110.003", "Brute Force: Password Spraying"),
                description=f"{ip} attempted {len(users)} distinct usernames "
                            f"({', '.join(users[:6])}{'...' if len(users) > 6 else ''}).",
                count=len(evs),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in evs[:3]],
            ))
        return alerts


class SSHSuccessAfterBruteForceDetector(BaseDetector):
    """A successful login from an IP that also produced many failures = likely breach."""

    name = "ssh_success_after_bruteforce"

    def __init__(self, min_failures: int = 10):
        self.min_failures = min_failures

    def run(self, events: Sequence[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        failures = _by_ip(events, (EventKind.SSH_FAILED, EventKind.SSH_INVALID_USER))
        accepts = _by_ip(events, (EventKind.SSH_ACCEPTED,))
        for ip, acc in accepts.items():
            fails = failures.get(ip, [])
            if len(fails) < self.min_failures:
                continue
            users = sorted({e.user for e in acc})
            first, last = time_span(fails + acc)
            alerts.append(Alert(
                detector=self.name,
                title="Successful SSH login after brute-force",
                severity=Severity.CRITICAL,
                source_ip=ip,
                mitre=MitreTechnique("T1078", "Valid Accounts"),
                description=f"{ip} logged in as {', '.join(users)} after "
                            f"{len(fails)} failed attempts — possible account compromise.",
                count=len(acc),
                first_seen=first, last_seen=last,
                evidence=[e.raw for e in acc[:3]],
            ))
        return alerts
