#!/usr/bin/env python3
"""ThreatTimeline: offline event correlation and threat-hunting CLI."""
import argparse, csv, json
from pathlib import Path
from threattimeline.engine import analyze

def main():
    parser=argparse.ArgumentParser(description="Correlate security events into an investigation timeline.")
    parser.add_argument("input", help="JSON file containing a list of security events")
    parser.add_argument("--output", default="reports/threattimeline-report.json")
    parser.add_argument("--csv", dest="csv_path", default=None, help="Optional findings CSV")
    parser.add_argument("--window-minutes", type=int, default=15)
    args=parser.parse_args()
    if args.window_minutes < 1: parser.error("--window-minutes must be positive")
    path=Path(args.input)
    if not path.is_file(): parser.error(f"input file not found: {path}")
    try:
        raw=json.loads(path.read_text(encoding="utf-8"))
        result=analyze(raw, args.window_minutes)
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    out=Path(args.output); out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(f"ThreatTimeline report: {out}")
    print(f"Events: {result['summary']['events']} | Correlation groups: {result['summary']['correlation_groups']} | Findings: {result['summary']['findings']}")
    for finding in result["findings"]:
        print(f"[{finding['severity']}] {finding['rule_id']} — {finding['title']}")
    if args.csv_path:
        cp=Path(args.csv_path); cp.parent.mkdir(parents=True,exist_ok=True)
        fields=["rule_id","severity","title","start","end","entities","evidence","recommendation"]
        with cp.open("w",newline="",encoding="utf-8") as f:
            writer=csv.DictWriter(f,fieldnames=fields); writer.writeheader()
            for finding in result["findings"]:
                row=finding.copy()
                for key in ("entities","evidence"): row[key]=" | ".join(map(str,row[key]))
                writer.writerow(row)
        print(f"CSV findings: {cp}")
if __name__=="__main__": main()
