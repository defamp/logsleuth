"""Detection rules."""

from .base import BaseDetector
from .ssh_bruteforce import (
    SSHBruteForceDetector,
    SSHPasswordSprayDetector,
    SSHSuccessAfterBruteForceDetector,
)
from .web import SensitivePathDetector, WebAttackDetector, WebScanningDetector


def default_detectors():
    """The standard detector set used by the CLI."""
    return [
        SSHBruteForceDetector(),
        SSHPasswordSprayDetector(),
        SSHSuccessAfterBruteForceDetector(),
        WebAttackDetector(),
        WebScanningDetector(),
        SensitivePathDetector(),
    ]


__all__ = [
    "BaseDetector",
    "SSHBruteForceDetector",
    "SSHPasswordSprayDetector",
    "SSHSuccessAfterBruteForceDetector",
    "WebAttackDetector",
    "WebScanningDetector",
    "SensitivePathDetector",
    "default_detectors",
]
