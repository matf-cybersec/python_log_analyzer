"""
Tests for the log parser.
Validates that each auth.log pattern is correctly parsed into LogEvent objects.
"""

from src.parser import LogEvent, parse_line


def test_failed_login_bad_password() -> None:
    """Parse a failed SSH login due to bad password."""
    line = "Jun 13 08:15:03 server1 sshd[2145]: Failed password for root from 192.168.1.50 port 54322 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "failed"
    assert event.reason == "bad password"
    assert event.username == "root"
    assert event.source_ip == "192.168.1.50"
    assert event.service == "sshd"
    assert event.host == "server1"


def test_failed_login_invalid_user() -> None:
    """Parse a failed SSH login due to invalid user."""
    line = "Jun 13 08:14:22 server1 sshd[2145]: Failed password for invalid user admin from 192.168.1.50 port 54321 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "failed"
    assert event.reason == "invalid user"
    assert event.username == "admin"
    assert event.source_ip == "192.168.1.50"


def test_successful_login() -> None:
    """Parse a successful SSH login."""
    line = "Jun 13 08:15:45 server1 sshd[2146]: Accepted password for alice from 192.168.1.20 port 54410 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "success"
    assert event.reason is None
    assert event.username == "alice"
    assert event.source_ip == "192.168.1.20"


def test_permission_denied() -> None:
    """Parse a permission denied event."""
    line = "Jun 13 08:16:00 server1 sshd[2147]: Permission denied for bob from 10.0.0.44 port 54411 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "failed"
    assert event.reason == "permission denied"
    assert event.username == "bob"
    assert event.source_ip == "10.0.0.44"


def test_connection_refused() -> None:
    """Parse a connection refused event."""
    line = "Jun 13 08:17:00 server1 sshd[2148]: Connection refused by authenticating user charlie from 10.20.30.40 port 54412 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "failed"
    assert event.reason == "connection refused"
    assert event.username == "charlie"
    assert event.source_ip == "10.20.30.40"


def test_sudo_event() -> None:
    """Parse a sudo privilege usage event."""
    line = "Jun 13 08:16:45 server1 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls"
    event = parse_line(line)

    assert event is not None
    assert event.outcome == "privilege_use"
    assert event.service == "sudo"
    assert event.username == "alice"
    assert event.source_ip is None


def test_unmatched_line() -> None:
    """Unmatched lines should return None."""
    line = "Jun 13 08:18:00 server1 kernel: Some random kernel message"
    event = parse_line(line)

    assert event is None


def test_empty_line() -> None:
    """Empty lines should return None."""
    event = parse_line("")
    assert event is None
