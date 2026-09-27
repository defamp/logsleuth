"""Offline unit tests for LogSleuth."""

from logsleuth.engine import Engine
from logsleuth.models import EventKind, Severity
from logsleuth.parsers import AuthLogParser, WebLogParser


# ---- parser tests -----------------------------------------------------------

def test_auth_parser_failed():
    line = "Oct 10 09:15:02 web01 sshd[2001]: Failed password for root from 203.0.113.66 port 40001 ssh2"
    ev = AuthLogParser().parse_line(line)
    assert ev.kind is EventKind.SSH_FAILED
    assert ev.source_ip == "203.0.113.66"
    assert ev.user == "root"
    assert ev.timestamp is not None


def test_auth_parser_invalid_user():
    line = "Oct 10 11:20:01 web01 sshd[3001]: Failed password for invalid user admin from 198.51.100.23 port 33001 ssh2"
    ev = AuthLogParser().parse_line(line)
    assert ev.kind is EventKind.SSH_INVALID_USER
    assert ev.user == "admin"


def test_auth_parser_accepted():
    line = "Oct 10 12:00:00 web01 sshd[4001]: Accepted publickey for deploy from 10.0.0.5 port 52000 ssh2"
    ev = AuthLogParser().parse_line(line)
    assert ev.kind is EventKind.SSH_ACCEPTED
    assert ev.user == "deploy"


def test_web_parser():
    line = '45.146.164.9 - - [10/Oct/2024:10:00:01 +0000] "GET /a?x=1 HTTP/1.1" 404 200 "-" "sqlmap/1.7"'
    ev = WebLogParser().parse_line(line)
    assert ev.kind is EventKind.HTTP_REQUEST
    assert ev.method == "GET"
    assert ev.status == 404
    assert ev.source_ip == "45.146.164.9"


# ---- detector / engine tests ------------------------------------------------

def _analyze(path):
    with open(path, encoding="utf-8") as fh:
        return Engine().analyze(fh.readlines())


def test_bruteforce_and_breach_detected():
    alerts = _analyze("samples/auth.log")
    titles = {a.title for a in alerts}
    assert "SSH brute-force attempt" in titles
    assert "Successful SSH login after brute-force" in titles
    # The breach should be CRITICAL and tied to the attacker IP.
    breach = next(a for a in alerts if "Successful" in a.title)
    assert breach.severity is Severity.CRITICAL
    assert breach.source_ip == "203.0.113.66"


def test_password_spray_detected():
    alerts = _analyze("samples/auth.log")
    spray = [a for a in alerts if a.detector == "ssh_password_spray"]
    assert spray and spray[0].source_ip == "198.51.100.23"


def test_web_attacks_detected():
    alerts = _analyze("samples/access.log")
    mitre_ids = {a.mitre.id for a in alerts}
    assert "T1190" in mitre_ids          # SQLi / XSS
    assert "T1595.003" in mitre_ids      # scanning (many 404s)
    assert "T1083" in mitre_ids          # sensitive path


def test_no_alerts_on_clean_input():
    clean = ["Oct 10 08:00:01 web01 sshd[1]: Accepted password for deploy from 10.0.0.5 port 1 ssh2"]
    assert Engine().analyze(clean) == []


def test_alerts_sorted_by_severity():
    alerts = _analyze("samples/auth.log")
    levels = [a.severity.level for a in alerts]
    assert levels == sorted(levels, reverse=True)
