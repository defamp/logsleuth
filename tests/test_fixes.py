"""Tests for IPv6 support, multi-signature web detection, year rollover and the CLI."""

import json
from datetime import datetime

import pytest

from logsleuth.cli import main
from logsleuth.engine import Engine
from logsleuth.models import EventKind
from logsleuth.parsers import AuthLogParser, WebLogParser


def _failed(ts, ip, user="root"):
    return f"{ts} web01 sshd[811]: Failed password for {user} from {ip} port 50001 ssh2"


# ---- IPv6 ---------------------------------------------------------------------


@pytest.mark.parametrize("ip", ["2001:db8::1", "::1", "fe80::1ff:fe23:4567:890a", "::ffff:192.0.2.7"])
def test_auth_parser_ipv6(ip):
    ev = AuthLogParser().parse_line(_failed("Oct 10 09:15:02", ip))
    assert ev.kind is EventKind.SSH_FAILED
    assert ev.source_ip == ip


def test_auth_parser_ipv6_accepted_and_invalid():
    acc = "Oct 10 12:00:00 web01 sshd[1]: Accepted publickey for deploy from 2001:db8::5 port 52000 ssh2"
    inv = "Oct 10 12:00:01 web01 sshd[1]: Invalid user oracle from 2001:db8::6 port 52001"
    assert AuthLogParser().parse_line(acc).source_ip == "2001:db8::5"
    assert AuthLogParser().parse_line(inv).kind is EventKind.SSH_INVALID_USER


@pytest.mark.parametrize("bogus", ["999.1.1.1", "1.2.3", "abc::xyz", "::::"])
def test_auth_parser_rejects_invalid_ips(bogus):
    assert AuthLogParser().parse_line(_failed("Oct 10 09:15:02", bogus)) is None


def test_ipv6_bruteforce_is_detected():
    lines = [_failed(f"Oct 10 10:00:{i:02d}", "2001:db8::1") for i in range(14)]
    alerts = Engine().analyze(lines)
    brute = [a for a in alerts if a.title == "SSH brute-force attempt"]
    assert brute and brute[0].source_ip == "2001:db8::1"
    assert brute[0].count == 14


def test_web_parser_ipv6_and_rejects_garbage():
    line = '2001:db8::7 - - [10/Oct/2024:10:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"'
    assert WebLogParser().parse_line(line).source_ip == "2001:db8::7"
    bad = '999.9.9.9 - - [10/Oct/2024:10:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"'
    assert WebLogParser().parse_line(bad) is None


# ---- web detector ---------------------------------------------------------------


def _web(path, ua="Mozilla/5.0", ip="203.0.113.5"):
    return f'{ip} - - [10/Oct/2024:10:00:01 +0000] "GET {path} HTTP/1.1" 200 5 "-" "{ua}"'


def _attack_titles(lines):
    return {a.title for a in Engine().analyze(lines) if a.mitre.id == "T1190"}


def test_request_with_several_payloads_reports_each():
    line = _web("/i.php?id=1%27%20UNION%20SELECT%20<img/src=x/onerror=alert(1)>")
    assert _attack_titles([line]) == {
        "Web attack: SQL injection",
        "Web attack: Cross-site scripting",
    }


def test_user_agent_payloads_are_inspected():
    shellshock = _web("/cgi-bin/status", ua="() { :; }; /bin/sh -c id")
    xss = _web("/", ua="<script>alert(1)</script>", ip="203.0.113.6")
    titles = _attack_titles([shellshock, xss])
    assert "Web attack: Command injection" in titles
    assert "Web attack: Cross-site scripting" in titles


def test_benign_request_and_user_agent_stay_quiet():
    line = _web("/products?page=2&sort=price", ua="Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
    assert _attack_titles([line]) == set()


# ---- syslog year -----------------------------------------------------------------


def test_default_year_is_current_year():
    ev = AuthLogParser().parse_line(_failed("Oct 10 09:15:02", "203.0.113.9"))
    assert ev.timestamp.year == datetime.now().year


def test_year_rolls_over_at_new_year():
    parser = AuthLogParser(year=2025)
    lines = [_failed("Dec 31 23:59:58", "203.0.113.9"), _failed("Jan  1 00:00:03", "203.0.113.9")]
    stamps = [e.timestamp for e in parser.parse(lines)]
    assert stamps == [datetime(2025, 12, 31, 23, 59, 58), datetime(2026, 1, 1, 0, 0, 3)]
    # A fresh run starts again from the configured year
    assert next(parser.parse(lines[:1])).timestamp.year == 2025


def test_bruteforce_across_new_year_is_one_burst():
    lines = [_failed(f"Dec 31 23:59:{50 + i}", "203.0.113.9") for i in range(6)]
    lines += [_failed(f"Jan  1 00:00:0{i}", "203.0.113.9") for i in range(6)]
    alerts = Engine(year=2025).analyze(lines)
    brute = [a for a in alerts if a.title == "SSH brute-force attempt"]
    assert brute and brute[0].count == 12


# ---- CLI + reports -----------------------------------------------------------------


def test_cli_json(capsys):
    code = main(["samples/auth.log", "--json"])
    out = json.loads(capsys.readouterr().out)
    alerts = out["alerts"] if isinstance(out, dict) else out
    assert any(a["title"] == "SSH brute-force attempt" for a in alerts)
    assert code == 1  # HIGH+ found


def test_cli_html_escapes_attacker_input(tmp_path, capsys):
    log = tmp_path / "access.log"
    log.write_text(_web("/?q=<script>alert(1)</script>", ua="<script>ua()</script>") + "\n")
    out = tmp_path / "r.html"
    main([str(log), "--html", str(out), "--no-color", "--summary"])
    page = out.read_text()
    assert "<script>alert(1)" not in page and "<script>ua()" not in page
    assert "Cross-site scripting" in page


def test_cli_year_flag(tmp_path, capsys):
    log = tmp_path / "auth.log"
    log.write_text("\n".join(_failed(f"Oct 10 10:00:{i:02d}", "203.0.113.9") for i in range(12)))
    main([str(log), "--json", "--year", "2019"])
    assert "2019-10-10" in capsys.readouterr().out


def test_cli_no_input_is_an_error(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert main([]) == 2


def test_cli_min_severity_filters(capsys):
    main(["samples/auth.log", "--json", "--min-severity", "critical"])
    out = json.loads(capsys.readouterr().out)
    alerts = out["alerts"] if isinstance(out, dict) else out
    assert alerts and all(a["severity"] == "critical" for a in alerts)
