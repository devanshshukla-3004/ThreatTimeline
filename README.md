# ThreatTimeline
**Day 15/100 — 100 Days • 100 Cybersecurity Projects**

ThreatTimeline is an offline-first Python tool that normalizes supplied security events, arranges them chronologically, groups events sharing an IP, and applies transparent rules to identify activity worth investigating.

## Features
- Normalize ISO-8601 timestamps to UTC and sort a unified timeline.
- Correlate events sharing a source IP into inspectable groups.
- Detect repeated authentication failures followed by success (TT-001).
- Flag a source attempting multiple usernames (TT-002).
- Flag security/audit log-clearing events (TT-003).
- Produce evidence, severity, recommendations, JSON reports and optional CSV findings.
- No third-party runtime dependencies.

## Quick start
Python 3.10+ recommended.
```bash
python -m unittest discover -s tests -v
python threattimeline.py samples/sample_events.json --output reports/threattimeline-report.json --csv reports/findings.csv
```

## Input format
Supply a JSON list of objects. Required fields: `timestamp` (ISO-8601), `event_type`, `source`. Optional fields include `event_id`, `source_ip`, `username`, `host`, and `details`. Example:
```json
{"timestamp":"2026-10-18T10:00:00Z","event_type":"failed_login","source":"linux-auth","source_ip":"203.0.113.10","username":"admin"}
```

## Detection rules
| ID | Detection | Severity |
|---|---|---|
| TT-001 | Successful login after 3+ failures from the same IP within the configured window | High |
| TT-002 | Failed/invalid authentication attempts against 3+ distinct usernames from one IP | Medium |
| TT-003 | Explicit security/audit log-cleared event | High |

Use `--window-minutes 15` to change the time window for TT-001. Correlation groups are IP-based and show shared attributes only; they do not prove events have the same cause.

## Safety and limitations
- Reads only the JSON file supplied by the user; no network activity, live collection, blocking, or system changes.
- Sample records use documentation-only IP ranges and synthetic events.
- Heuristic detections can miss variants and generate false positives.
- A detection is an investigation lead, not proof of compromise.
- This is an educational project, not a complete SIEM or incident-response platform.

## Project layout
```text
threattimeline.py
threattimeline/engine.py
tests/test_engine.py
samples/sample_events.json
reports/.gitkeep
requirements.txt
LICENSE
```
