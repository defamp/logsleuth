"""Rendering for LogSleuth: console, JSON and HTML."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import Alert, Severity

_SEV_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def _sev(sev: Severity) -> Text:
    return Text(f" {_SEV_LABEL[sev]} ", style=_SEV_STYLE[sev])


def print_alerts(alerts: List[Alert], console: Console) -> None:
    if not alerts:
        console.print(Panel("[green]No alerts — no suspicious activity detected.[/]",
                            border_style="green"))
        return
    for a in alerts:
        body = Table.grid(padding=(0, 1))
        body.add_column(style="bold", justify="right")
        body.add_column()
        body.add_row("Source IP:", f"[cyan]{a.source_ip}[/]")
        body.add_row("MITRE:", f"[magenta]{a.mitre.id}[/] {a.mitre.name}")
        body.add_row("Events:", str(a.count))
        if a.first_seen and a.last_seen:
            body.add_row("Window:", f"{a.first_seen} → {a.last_seen}")
        body.add_row("Detail:", a.description)
        if a.evidence:
            body.add_row("Evidence:", Text(a.evidence[0], style="dim"))
        title = Text.assemble(_sev(a.severity), (f"  {a.title}", "bold"))
        console.print(Panel(body, title=title, title_align="left",
                            border_style=_SEV_STYLE[a.severity].split()[-1]))


def print_summary(alerts: List[Alert], console: Console) -> None:
    table = Table(title="LogSleuth — Detection Summary", header_style="bold cyan", expand=True)
    table.add_column("Severity", justify="center")
    table.add_column("Alert")
    table.add_column("Source IP", justify="center")
    table.add_column("MITRE", justify="center")
    table.add_column("Events", justify="right")
    for a in alerts:
        table.add_row(_sev(a.severity), a.title, a.source_ip, a.mitre.id, str(a.count))
    console.print(table)
    counts = Counter(a.severity for a in alerts)
    line = "  ".join(f"{_SEV_LABEL[s]}: {counts.get(s, 0)}"
                     for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW))
    console.print(f"[bold]{len(alerts)} alert(s)[/]  |  {line}")


def to_json(alerts: List[Alert]) -> str:
    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "alert_count": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }
    return json.dumps(payload, indent=2)


_HTML_COLOR = {
    Severity.CRITICAL: "#f87171",
    Severity.HIGH: "#fb923c",
    Severity.MEDIUM: "#fbbf24",
    Severity.LOW: "#22d3ee",
    Severity.INFO: "#94a3b8",
}


def to_html(alerts: List[Alert]) -> str:
    cards = []
    for a in alerts:
        color = _HTML_COLOR[a.severity]
        evidence = html.escape(a.evidence[0]) if a.evidence else ""
        cards.append(
            "<div class='card' style='border-left:4px solid {c}'>"
            "<div class='row'><span class='sev' style='background:{c}'>{sev}</span>"
            "<span class='title'>{title}</span></div>"
            "<div class='meta'><b>{ip}</b> &middot; <span class='mitre'>{mid}</span> {mname}"
            " &middot; {count} event(s)</div>"
            "<div class='desc'>{desc}</div>"
            "<pre class='ev'>{ev}</pre></div>".format(
                c=color, sev=_SEV_LABEL[a.severity], title=html.escape(a.title),
                ip=html.escape(a.source_ip), mid=html.escape(a.mitre.id),
                mname=html.escape(a.mitre.name), count=a.count,
                desc=html.escape(a.description), ev=evidence,
            )
        )
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return _HTML_TEMPLATE.format(cards="\n".join(cards) or "<p>No alerts.</p>",
                                 generated=generated, count=len(alerts))


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LogSleuth Report</title>
<style>
  body{{font-family:system-ui,Segoe UI,Arial,sans-serif;background:#0a0e1a;color:#e6edf7;margin:0;padding:32px}}
  h1{{margin:0 0 4px}} .top{{color:#94a3b8;font-size:.85rem;margin-bottom:24px}}
  .card{{background:#151c2e;border:1px solid #243049;border-radius:10px;padding:16px 18px;margin-bottom:12px}}
  .row{{display:flex;align-items:center;gap:10px}}
  .sev{{color:#04121a;font-weight:700;font-size:.72rem;padding:2px 8px;border-radius:5px}}
  .title{{font-weight:700}}
  .meta{{color:#cbd5e1;font-size:.85rem;margin:8px 0}}
  .mitre{{color:#c084fc;font-family:ui-monospace,monospace}}
  .desc{{color:#94a3b8;font-size:.9rem;margin-bottom:8px}}
  .ev{{background:#0a0e1a;border:1px solid #1c2438;border-radius:6px;padding:8px;overflow-x:auto;
      font-size:.78rem;color:#7c8aa5;margin:0}}
</style></head><body>
<h1>🔍 LogSleuth Report</h1>
<div class="top">Generated {generated} &middot; {count} alert(s)</div>
{cards}
</body></html>
"""
