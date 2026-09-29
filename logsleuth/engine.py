"""Ties parsing and detection together."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence

from .detectors import default_detectors
from .detectors.base import BaseDetector
from .models import Alert, Event, Severity
from .parsers import AuthLogParser, WebLogParser


class Engine:
    def __init__(self, detectors: Sequence[BaseDetector] = None, year: Optional[int] = None):
        self.detectors = list(detectors) if detectors is not None else default_detectors()
        self.parsers = [AuthLogParser(year=year), WebLogParser()]

    def parse(self, lines: Iterable[str]) -> List[Event]:
        """Run every parser over the lines and merge the events."""
        lines = list(lines)
        events: List[Event] = []
        for parser in self.parsers:
            events.extend(parser.parse(lines))
        return events

    def detect(self, events: Sequence[Event]) -> List[Alert]:
        alerts: List[Alert] = []
        for detector in self.detectors:
            alerts.extend(detector.run(events))
        # Most severe first, then by volume.
        alerts.sort(key=lambda a: (a.severity.level, a.count), reverse=True)
        return alerts

    def analyze(self, lines: Iterable[str]) -> List[Alert]:
        return self.detect(self.parse(lines))


def filter_min_severity(alerts: Sequence[Alert], minimum: Severity) -> List[Alert]:
    return [a for a in alerts if a.severity.level >= minimum.level]
