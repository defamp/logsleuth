"""Base detector interface + shared helpers."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Sequence

from ..models import Alert, Event


class BaseDetector:
    """Consumes a stream of events and emits alerts."""

    name = "base"

    def run(self, events: Sequence[Event]) -> List[Alert]:
        raise NotImplementedError


def time_span(events: Sequence[Event]):
    """Return (first_seen, last_seen) datetimes, ignoring events without a ts."""
    stamps = [e.timestamp for e in events if e.timestamp is not None]
    if not stamps:
        return None, None
    return min(stamps), max(stamps)


def within_window(events: Sequence[Event], threshold: int, window_seconds: int) -> bool:
    """True if >= ``threshold`` events fall inside any ``window_seconds`` span.

    Uses a sliding window over sorted timestamps. If timestamps are missing,
    falls back to a plain count.
    """
    stamps: List[datetime] = sorted(e.timestamp for e in events if e.timestamp)
    if len(stamps) < threshold:
        return len(events) >= threshold and not stamps
    left = 0
    for right in range(len(stamps)):
        while (stamps[right] - stamps[left]).total_seconds() > window_seconds:
            left += 1
        if right - left + 1 >= threshold:
            return True
    return False
