"""Base parser interface."""

from __future__ import annotations

from typing import Iterable, Iterator

from ..models import Event


class BaseParser:
    """Turns raw log lines into normalised :class:`Event` objects.

    A parser silently ignores lines it does not understand, so several parsers
    can be run over the same file.
    """

    name = "base"

    def parse_line(self, line: str):
        raise NotImplementedError

    def parse(self, lines: Iterable[str]) -> Iterator[Event]:
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            event = self.parse_line(line)
            if event is not None:
                yield event
