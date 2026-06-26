from __future__ import annotations

import argparse
import sys
from pathlib import Path

from src.analyzer import analyze_events
from src.parser import parse_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze Linux auth logs for login activity.")
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument(
        "--threshold",
        type=int,
        default=3,
        help="Failed login count from one IP before flagging it as suspicious",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    log_path = Path(args.logfile)

    if not log_path.is_file():
        print(f"Error: file not found: {log_path}", file=sys.stderr)
        return 1

    events = parse_file(log_path)
    result = analyze_events(events, suspicious_threshold=args.threshold)

    print("Log Analysis Summary")
    print("-" * 20)
    print(f"Total parsed events: {result.total_events}")
    print(f"Successful logins: {result.successful_logins}")
    print(f"Failed logins: {result.failed_logins}")

    if result.suspicious_ips:
        print("Suspicious IPs:")
        for ip, count in result.suspicious_ips:
            print(f"- {ip}: {count} failed attempts")
    else:
        print("Suspicious IPs: none")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())