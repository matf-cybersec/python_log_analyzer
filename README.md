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
- The walkthrough PDF should stay local and is ignored by git

## Next Steps

1. Build the log parser for authentication and system events.
2. Add failed-login detection and suspicious IP thresholds.
3. Print a clear terminal summary for SOC-style review.
4. Add optional JSON export after the core CLI works.

