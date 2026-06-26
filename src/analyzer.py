from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from src.parser import LogEvent


@dataclass
class AnalysisResult:
    total_events: int
    successful_logins: int
    failed_logins: int
    suspicious_ips: list[tuple[str, int]]


def analyze_events(events: list[LogEvent], suspicious_threshold: int = 3) -> AnalysisResult:
    failed_by_ip: Counter[str] = Counter()
    successful_logins = 0
    failed_logins = 0

    for event in events:
        if event.outcome == "success":
            successful_logins += 1
        elif event.outcome == "failed":
            failed_logins += 1
            if event.source_ip:
                failed_by_ip[event.source_ip] += 1

    suspicious_ips = [
        (ip, count)
        for ip, count in failed_by_ip.most_common()
        if count >= suspicious_threshold
    ]

    return AnalysisResult(
        total_events=len(events),
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_ips=suspicious_ips,
    )