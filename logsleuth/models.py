"""Core data models for LogSleuth."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class EventKind(str, Enum):
    SSH_FAILED = "ssh_failed"          # failed password (known user)
    SSH_INVALID_USER = "ssh_invalid"   # failed for a non-existent user
    SSH_ACCEPTED = "ssh_accepted"      # successful login
    HTTP_REQUEST = "http_request"      # a single web request


@dataclass
class Event:
    """A single normalised log event."""

    kind: EventKind
    timestamp: Optional[datetime]
    source_ip: str
    raw: str
    user: Optional[str] = None
    # Web-specific fields live here to keep the model flat.
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    user_agent: Optional[str] = None


@dataclass
class MitreTechnique:
    id: str
    name: str

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.id} {self.name}"


@dataclass
class Alert:
    """A detection finding, ready to display or ship to a SIEM."""

    detector: str
    title: str
    severity: Severity
    source_ip: str
    mitre: MitreTechnique
    description: str
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detector": self.detector,
            "title": self.title,
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "mitre": {"id": self.mitre.id, "name": self.mitre.name},
            "description": self.description,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "evidence": self.evidence,
        }
