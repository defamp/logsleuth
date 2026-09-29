"""Command-line interface for LogSleuth."""

from __future__ import annotations

import argparse
import sys
from typing import List

from rich.console import Console

from . import __version__
from .detectors import default_detectors
from .detectors.ssh_bruteforce import SSHBruteForceDetector
from .engine import Engine, filter_min_severity
from .models import Severity
from .report import print_alerts, print_summary, to_html, to_json


def _read_lines(paths: List[str]) -> List[str]:
    lines: List[str] = []
    if paths:
        for path in paths:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines.extend(fh.readlines())
    elif not sys.stdin.isatty():
        lines.extend(sys.stdin.readlines())
    return lines


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logsleuth",
        description="Analyze auth/web logs for attacks and map findings to MITRE ATT&CK.",
    )
    p.add_argument("logfiles", nargs="*", help="log files to analyze (or pipe via stdin)")
    p.add_argument("--summary", action="store_true", help="compact summary table")
    p.add_argument("--json", action="store_true", help="JSON output to stdout")
    p.add_argument("--html", metavar="PATH", help="write an HTML report")
    p.add_argument("--min-severity", choices=[s.value for s in Severity],
                   default="low", help="only show alerts at/above this severity")
    p.add_argument("--bruteforce-threshold", type=int, default=10,
                   help="failed SSH logins per IP before alerting (default 10)")
    p.add_argument("--year", type=int,
                   help="year of the first syslog line (auth.log has no year; default: current "
                        "year, rolling over at New Year)")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")
    p.add_argument("-V", "--version", action="version", version=f"logsleuth {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console = Console(no_color=args.no_color)
    err = Console(stderr=True, no_color=args.no_color)

    lines = _read_lines(args.logfiles)
    if not lines:
        err.print("[red]No input.[/] Pass one or more log files, or pipe logs via stdin.")
        return 2

    # Allow tuning the brute-force threshold from the CLI.
    detectors = default_detectors()
    detectors[0] = SSHBruteForceDetector(threshold=args.bruteforce_threshold)

    engine = Engine(detectors=detectors, year=args.year)
    events = engine.parse(lines)
    alerts = engine.detect(events)
    alerts = filter_min_severity(alerts, Severity(args.min_severity))

    if args.json:
        print(to_json(alerts))
    elif args.summary:
        print_summary(alerts, console)
    else:
        console.print(f"[dim]Parsed {len(events)} events from {len(lines)} lines.[/]")
        print_alerts(alerts, console)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(alerts))
        console.print(f"[green]HTML report written:[/] {args.html}")

    # Non-zero exit if anything HIGH or above was found (handy for CI / cron).
    serious = any(a.severity.level >= Severity.HIGH.level for a in alerts)
    return 1 if serious else 0


if __name__ == "__main__":
    sys.exit(main())
