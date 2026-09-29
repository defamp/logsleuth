"""Parser for Apache/Nginx combined access logs."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Optional

from ..models import Event, EventKind
from .base import BaseParser

# 127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /p HTTP/1.1" 200 1234 "ref" "ua"
_COMBINED = re.compile(
    r'^(?P<ip>[0-9A-Fa-f:.]+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def _parse_ts(raw: str) -> Optional[datetime]:
    # e.g. 10/Oct/2024:13:55:36 +0000
    try:
        return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


class WebLogParser(BaseParser):
    name = "web"

    def parse_line(self, line: str) -> Optional[Event]:
        m = _COMBINED.search(line)
        if not m:
            return None
        try:
            ipaddress.ip_address(m.group("ip"))  # IPv4 or IPv6
        except ValueError:
            return None
        return Event(
            kind=EventKind.HTTP_REQUEST,
            timestamp=_parse_ts(m.group("ts")),
            source_ip=m.group("ip"),
            method=m.group("method"),
            path=m.group("path"),
            status=int(m.group("status")),
            user_agent=m.group("ua"),
            raw=line,
        )
