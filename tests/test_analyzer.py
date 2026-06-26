"""
Tests for the log analyzer.
Validates counting logic and suspicious IP detection.
"""

from src.analyzer import analyze_events
from src.parser import LogEvent


def test_count_successful_logins() -> None:
    """Verify successful login counting."""
    events = [
        LogEvent(
            timestamp="Jun 13 08:15:45",
            host="server1",
            service="sshd",
            username="alice",
            source_ip="192.168.1.20",
            outcome="success",
            reason=None,
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:16:00",
            host="server1",
            service="sshd",
            username="bob",
            source_ip="192.168.1.21",
            outcome="success",
            reason=None,
            raw_line="",
        ),
    ]

    result = analyze_events(events)
    assert result.total_events == 2
    assert result.successful_logins == 2
    assert result.failed_logins == 0


def test_count_failed_logins() -> None:
    """Verify failed login counting."""
    events = [
        LogEvent(
            timestamp="Jun 13 08:15:03",
            host="server1",
            service="sshd",
            username="root",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="bad password",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:14:22",
            host="server1",
            service="sshd",
            username="admin",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="invalid user",
            raw_line="",
        ),
    ]

    result = analyze_events(events)
    assert result.total_events == 2
    assert result.successful_logins == 0
    assert result.failed_logins == 2


def test_suspicious_ip_detection() -> None:
    """Verify suspicious IP flagging with threshold."""
    events = [
        LogEvent(
            timestamp="Jun 13 08:14:00",
            host="server1",
            service="sshd",
            username="user1",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="bad password",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:15:00",
            host="server1",
            service="sshd",
            username="user2",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="bad password",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:16:00",
            host="server1",
            service="sshd",
            username="user3",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="invalid user",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:17:00",
            host="server1",
            service="sshd",
            username="alice",
            source_ip="192.168.1.20",
            outcome="success",
            reason=None,
            raw_line="",
        ),
    ]

    result = analyze_events(events, suspicious_threshold=3)
    assert len(result.suspicious_ips) == 1
    assert result.suspicious_ips[0][0] == "192.168.1.50"
    assert result.suspicious_ips[0][1] == 3


def test_no_suspicious_ips_below_threshold() -> None:
    """Verify no IPs are flagged if they don't meet the threshold."""
    events = [
        LogEvent(
            timestamp="Jun 13 08:14:00",
            host="server1",
            service="sshd",
            username="user1",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="bad password",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:15:00",
            host="server1",
            service="sshd",
            username="alice",
            source_ip="192.168.1.20",
            outcome="success",
            reason=None,
            raw_line="",
        ),
    ]

    result = analyze_events(events, suspicious_threshold=5)
    assert len(result.suspicious_ips) == 0


def test_mixed_outcomes() -> None:
    """Verify mixed successful and failed outcomes are counted correctly."""
    events = [
        LogEvent(
            timestamp="Jun 13 08:14:00",
            host="server1",
            service="sshd",
            username="user1",
            source_ip="192.168.1.50",
            outcome="failed",
            reason="bad password",
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:15:00",
            host="server1",
            service="sshd",
            username="alice",
            source_ip="192.168.1.20",
            outcome="success",
            reason=None,
            raw_line="",
        ),
        LogEvent(
            timestamp="Jun 13 08:16:00",
            host="server1",
            service="sudo",
            username="alice",
            source_ip=None,
            outcome="privilege_use",
            reason=None,
            raw_line="",
        ),
    ]

    result = analyze_events(events, suspicious_threshold=3)
    assert result.total_events == 3
    assert result.successful_logins == 1
    assert result.failed_logins == 1
