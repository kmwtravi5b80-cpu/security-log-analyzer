# Project 1: Security Log Analyzer

## Overview
A Python command-line tool that reviews a text authentication log, counts successful and failed authentication events, groups failed attempts by source IP, and flags sources that meet a configurable review threshold.

## Skills demonstrated
- Python file handling and regular expressions
- Log parsing and event classification
- Basic incident triage and reporting
- Defensive security monitoring

## Requirements
- Python 3.9 or newer
- No third-party packages

## Run
From this project folder:

```bash
python log_analyzer.py sample_data/auth.log
python log_analyzer.py sample_data/auth.log --threshold 3
```

On Kali/Linux, use `python3` if `python` is not mapped:

```bash
python3 log_analyzer.py sample_data/auth.log --threshold 3
```

## Expected result
The sample contains 5 failed authentication events and 2 successful events. `198.51.100.23` has 4 failed attempts and should be marked `[REVIEW]` with the default threshold of 5 only if you lower it to 3; this is intentionally a lab dataset.

## Safe use
Use only logs you own or are authorized to analyze. The IP addresses in the sample are documentation-only example ranges, not real attacker attribution. Repeated failures are indicators for investigation, not proof of compromise.

## Possible improvements
- Parse Windows Event Logs exported as CSV
- Export findings to JSON/CSV
- Add time-window analysis and alerting
