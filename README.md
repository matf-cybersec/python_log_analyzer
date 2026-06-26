# Log Analyzer

A beginner-friendly Python cybersecurity project for a SOC Analyst portfolio.

## Status

Work in progress. The repository currently contains the project scaffold, local walkthrough notes, and the folder structure needed for the first implementation pass.

## Goal

Analyze local authentication and system log files to identify failed logins, count successful and failed authentication events, flag suspicious IP addresses, and print a terminal summary report. JSON export can be added later if needed.

## Planned Structure

- `src/` - core parsing, analysis, and reporting logic
- `data/samples/` - sample logs for testing
- `data/outputs/` - generated reports and exports
- `tests/` - small checks for parser and detection logic
- `docs/walkthrough.md` - local walkthrough source for a PDF export

## Notes

- Standard library first
- No database
- No web interface
- Designed to run locally with `python main.py logfile.log`

## How to Use

### Run the analyzer on a log file

```bash
python main.py data/samples/auth_sample.log
```

### Run with a custom suspicious IP threshold (default is 3 failed attempts)

```bash
python main.py data/samples/auth_sample.log --threshold 5
```

### Run the test suite

All parser and analyzer tests are in `tests/`. To run them:

```bash
python3 -c "
import sys
sys.path.insert(0, '.')
from tests.test_parser import *
from tests.test_analyzer import *

tests = [
    test_failed_login_bad_password,
    test_failed_login_invalid_user,
    test_successful_login,
    test_permission_denied,
    test_connection_refused,
    test_sudo_event,
    test_unmatched_line,
    test_empty_line,
    test_count_successful_logins,
    test_count_failed_logins,
    test_suspicious_ip_detection,
    test_no_suspicious_ips_below_threshold,
    test_mixed_outcomes,
]

passed = 0
for t in tests:
    try:
        t()
        passed += 1
    except Exception as e:
        print(f'Failed: {e}')

print(f'{passed}/{len(tests)} tests passed')
"
```

### Supported log event types

- **Failed SSH login (bad password)**: detects password authentication failures
- **Failed SSH login (invalid user)**: detects login attempts against non-existent accounts  
- **Successful SSH login**: counts successful password-based logins
- **Permission denied**: detects SSH permission errors
- **Connection refused**: detects refused authentication attempts
- **Sudo privilege usage**: tracks sudo command execution

### Output

The analyzer prints a summary showing:
- Total parsed events
- Successful logins
- Failed logins
- Suspicious IPs (IPs with failed logins exceeding the threshold)

Example output:
```
Log Analysis Summary
--------------------
Total parsed events: 8
Successful logins: 2
Failed logins: 5
Suspicious IPs:
- 192.168.1.50: 3 failed attempts
```

## Next Steps

1. JSON export for downstream analysis
2. Support for more log sources (auth.log variations, syslog formats)
3. Time-window-based detection (failures within specific time periods)
