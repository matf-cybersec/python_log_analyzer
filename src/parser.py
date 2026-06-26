from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


FAILED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Failed password for (?:(?P<invalid_user>invalid user)\s+)?"
    r"(?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

SUCCESSFUL_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

PERMISSION_DENIED_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Permission denied for (?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

CONNECTION_REFUSED_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"Connection (?:closed|refused) by authenticating user (?P<username>\S+) from (?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

SUDO_RE = re.compile(
    r"^(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+sudo:\s+(?P<username>\S+)\s+:"
)


@dataclass(slots=True)
class LogEvent:
    timestamp: str
    host: str
    service: str
    username: str | None
    source_ip: str | None
    outcome: str
    reason: str | None
    raw_line: str


def parse_line(line: str) -> LogEvent | None:
    line = line.rstrip("\n")

    match = FAILED_LOGIN_RE.match(line)
    if match:
        invalid_user = match.group("invalid_user") is not None
        return LogEvent(
            timestamp=match.group("timestamp"),
            host=match.group("host"),
            service="sshd",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            outcome="failed",
            reason="invalid user" if invalid_user else "bad password",
            raw_line=line,
        )

    match = SUCCESSFUL_LOGIN_RE.match(line)
    if match:
        return LogEvent(
            timestamp=match.group("timestamp"),
            host=match.group("host"),
            service="sshd",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            outcome="success",
            reason=None,
            raw_line=line,
        )

    match = PERMISSION_DENIED_RE.match(line)
    if match:
        return LogEvent(
            timestamp=match.group("timestamp"),
            host=match.group("host"),
            service="sshd",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            outcome="failed",
            reason="permission denied",
            raw_line=line,
        )

    match = CONNECTION_REFUSED_RE.match(line)
    if match:
        return LogEvent(
            timestamp=match.group("timestamp"),
            host=match.group("host"),
            service="sshd",
            username=match.group("username"),
            source_ip=match.group("source_ip"),
            outcome="failed",
            reason="connection refused",
            raw_line=line,
        )

    match = SUDO_RE.match(line)
    if match:
        return LogEvent(
            timestamp=match.group("timestamp"),
            host=match.group("host"),
            service="sudo",
            username=match.group("username"),
            source_ip=None,
            outcome="privilege_use",
            reason=None,
            raw_line=line,
        )

    return None


def parse_lines(lines: Iterable[str]) -> list[LogEvent]:
    events: list[LogEvent] = []
    for line in lines:
        event = parse_line(line)
        if event is not None:
            events.append(event)
    return events


def parse_file(path: Path) -> list[LogEvent]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return parse_lines(handle)