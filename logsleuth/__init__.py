"""LogSleuth — a log analyzer & detection engine for SOC / blue teams.

Parses Linux auth logs and web access logs, runs detection rules for common
attacks (SSH brute force, password spraying, web scanning, injection attempts),
and maps each finding to MITRE ATT&CK.
"""

__version__ = "1.0.0"
__author__ = "Defa Mulya Pratama"
