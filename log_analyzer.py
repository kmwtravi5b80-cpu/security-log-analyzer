#!/usr/bin/env python3
"""
Security Log Analyzer
A beginner-friendly defensive tool that scans an authentication log and
summarizes failed logins by source IP address.

Usage:
    python log_analyzer.py sample_data/auth.log
    python log_analyzer.py sample_data/auth.log --threshold 3
"""
import argparse
import re
from collections import Counter
from pathlib import Path

# Supports common Linux SSH auth.log messages and the included sample format.
IP_RE = re.compile(r"(?:from\s+|src=)(\d{1,3}(?:\.\d{1,3}){3})")

def analyze_log(path: Path, threshold: int):
    failed_by_ip = Counter()
    total_failed = 0
    total_success = 0
    unreadable = 0

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise SystemExit(f"Could not read log file: {exc}")

    for line in lines:
        lower = line.lower()
        if "failed password" in lower or "authentication failure" in lower or "login failed" in lower:
            total_failed += 1
            match = IP_RE.search(line)
            if match:
                failed_by_ip[match.group(1)] += 1
        elif "accepted password" in lower or "accepted publickey" in lower or "login successful" in lower:
            total_success += 1

    print("\n=== SECURITY LOG ANALYSIS ===")
    print(f"File: {path}")
    print(f"Total lines: {len(lines)}")
    print(f"Successful authentication events: {total_success}")
    print(f"Failed authentication events: {total_failed}")
    print("\nFailed attempts by source IP:")
    if not failed_by_ip:
        print("  No source IP addresses found in failed-login events.")
    else:
        for ip, count in failed_by_ip.most_common():
            flag = "  [REVIEW]" if count >= threshold else ""
            print(f"  {ip:<18} {count:>4}{flag}")

    suspicious = [(ip, count) for ip, count in failed_by_ip.items() if count >= threshold]
    print("\nAssessment:")
    if suspicious:
        print(f"  {len(suspicious)} source IP(s) reached the review threshold ({threshold}).")
        print("  Investigate these events; repeated failures alone do not prove an attack.")
    else:
        print("  No source IP reached the configured review threshold.")
    print("  This tool provides triage support, not a definitive security verdict.")

def main():
    parser = argparse.ArgumentParser(description="Analyze authentication logs for repeated failed logins.")
    parser.add_argument("logfile", type=Path, help="Path to a text authentication log")
    parser.add_argument("--threshold", type=int, default=5, help="Flag IPs with this many or more failures (default: 5)")
    args = parser.parse_args()
    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    analyze_log(args.logfile, args.threshold)

if __name__ == "__main__":
    main()
