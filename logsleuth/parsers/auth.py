"""Parser for Linux ``auth.log`` / syslog SSH events."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from ..models import Event, EventKind
from .base import BaseParser

# syslog timestamp like: "Oct 10 13:55:36"
_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

_FAILED = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Failed password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_ACCEPTED = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
_INVALID = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Invalid user (?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _parse_ts(raw: str, year: int) -> Optional[datetime]:
    try:
        mon, day, clock = raw.split()
        month = _MONTHS.index(mon) + 1
        hh, mm, ss = (int(x) for x in clock.split(":"))
        return datetime(year, month, int(day), hh, mm, ss)
    except (ValueError, IndexError):
        return None


class AuthLogParser(BaseParser):
    name = "auth"

    def __init__(self, year: int = 2024):
        # syslog lines omit the year; assume one so time deltas are consistent.
        self.year = year

    def parse_line(self, line: str) -> Optional[Event]:
        m = _FAILED.search(line)
        if m:
            kind = EventKind.SSH_INVALID_USER if m.group("invalid") else EventKind.SSH_FAILED
            return Event(
                kind=kind,
                timestamp=_parse_ts(m.group("ts"), self.year),
                source_ip=m.group("ip"),
                user=m.group("user"),
                raw=line,
            )
        m = _ACCEPTED.search(line)
        if m:
            return Event(
                kind=EventKind.SSH_ACCEPTED,
                timestamp=_parse_ts(m.group("ts"), self.year),
                source_ip=m.group("ip"),
                user=m.group("user"),
                raw=line,
            )
        m = _INVALID.search(line)
        if m:
            return Event(
                kind=EventKind.SSH_INVALID_USER,
                timestamp=_parse_ts(m.group("ts"), self.year),
                source_ip=m.group("ip"),
                user=m.group("user"),
                raw=line,
            )
        return None
