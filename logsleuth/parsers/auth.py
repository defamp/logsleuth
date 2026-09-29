"""Parser for Linux ``auth.log`` / syslog SSH events."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Iterable, Iterator, Optional

from ..models import Event, EventKind
from .base import BaseParser

# syslog timestamp like: "Oct 10 13:55:36"
_TS = r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"

# IPv4 or IPv6; validated with the ipaddress module after matching.
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"

_FAILED = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Failed password for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from " + _IP + r"(?:\s|$)"
)
_ACCEPTED = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from " + _IP + r"(?:\s|$)"
)
_INVALID = re.compile(
    _TS + r".*sshd\[\d+\]:\s+Invalid user (?P<user>\S+) "
    r"from " + _IP + r"(?:\s|$)"
)

# A timestamp this far *before* the previous one means the log crossed New
# Year (syslog lines carry no year), e.g. "Dec 31 23:59" followed by "Jan 1".
_ROLLOVER_GAP = timedelta(days=180)

_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def _parse_ts(raw: str, year: int) -> Optional[datetime]:
    try:
        mon, day, clock = raw.split()
        month = _MONTHS.index(mon) + 1
        hh, mm, ss = (int(x) for x in clock.split(":"))
        return datetime(year, month, int(day), hh, mm, ss)
    except (ValueError, IndexError):
        return None


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class AuthLogParser(BaseParser):
    name = "auth"

    def __init__(self, year: Optional[int] = None):
        # syslog lines omit the year: start from the given one (default: this
        # year) and roll over when the timestamps wrap from December to January.
        self.start_year = year if year is not None else datetime.now().year
        self.year = self.start_year
        self._last: Optional[datetime] = None

    def parse(self, lines: Iterable[str]) -> Iterator[Event]:
        self.year, self._last = self.start_year, None  # each run starts fresh
        return super().parse(lines)

    def _timestamp(self, raw: str) -> Optional[datetime]:
        ts = _parse_ts(raw, self.year)
        if ts is not None and self._last is not None and ts < self._last - _ROLLOVER_GAP:
            self.year += 1
            ts = _parse_ts(raw, self.year)
        if ts is not None:
            self._last = ts
        return ts

    def parse_line(self, line: str) -> Optional[Event]:
        for pattern, kind in (
            (_FAILED, None),
            (_ACCEPTED, EventKind.SSH_ACCEPTED),
            (_INVALID, EventKind.SSH_INVALID_USER),
        ):
            m = pattern.search(line)
            if not m:
                continue
            if not _valid_ip(m.group("ip")):
                return None
            if kind is None:  # "Failed password", with or without "invalid user"
                kind = EventKind.SSH_INVALID_USER if m.group("invalid") else EventKind.SSH_FAILED
            return Event(
                kind=kind,
                timestamp=self._timestamp(m.group("ts")),
                source_ip=m.group("ip"),
                user=m.group("user"),
                raw=line,
            )
        return None
