"""Normalization, chronological ordering, correlation and explainable detections."""
from datetime import datetime, timezone
from collections import defaultdict

REQUIRED = {"timestamp", "event_type", "source"}
def _timestamp(value):
    if not isinstance(value,str) or not value.strip():
        raise ValueError("Each event needs a non-empty ISO-8601 timestamp")
    try:
        parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid ISO-8601 timestamp: {value}") from exc
    if parsed.tzinfo is None: parsed=parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)

def normalize(events):
    if not isinstance(events,list): raise TypeError("Input JSON must be a list of event objects")
    normalized=[]
    for index,item in enumerate(events,1):
        if not isinstance(item,dict): raise TypeError(f"Event {index} must be an object")
        missing=REQUIRED-item.keys()
        if missing: raise ValueError(f"Event {index} missing required fields: {', '.join(sorted(missing))}")
        dt=_timestamp(item["timestamp"])
        normalized.append({
            "event_id":str(item.get("event_id",f"event-{index}")),
            "timestamp":dt.isoformat().replace("+00:00","Z"),
            "_dt":dt,
            "event_type":str(item["event_type"]).strip().lower(),
            "source":str(item["source"]).strip(),
            "username":str(item.get("username","")).strip(),
            "source_ip":str(item.get("source_ip","")).strip(),
            "host":str(item.get("host","")).strip(),
            "details":str(item.get("details","")).strip(),
        })
    normalized.sort(key=lambda e:(e["_dt"],e["event_id"]))
    return normalized

def analyze(raw_events, window_minutes=15):
    if window_minutes < 1: raise ValueError("window_minutes must be positive")
    events=normalize(raw_events)
    by_ip=defaultdict(list); by_user=defaultdict(list)
    for event in events:
        if event["source_ip"]: by_ip[event["source_ip"]].append(event)
        if event["username"]: by_user[event["username"]].append(event)
    findings=[]
    # Detect a sequence of at least three failures followed by success from the same IP.
    for ip, group in by_ip.items():
        failures=[]
        for event in group:
            if event["event_type"] in {"failed_login","authentication_failure","login_failed"}:
                failures.append(event)
            elif event["event_type"] in {"successful_login","authentication_success","login_success"}:
                prior=[f for f in failures if 0 <= (event["_dt"]-f["_dt"]).total_seconds() <= window_minutes*60]
                if len(prior)>=3:
                    findings.append({
                        "rule_id":"TT-001","severity":"HIGH","title":"Successful login after repeated failures",
                        "start":prior[0]["timestamp"],"end":event["timestamp"],
                        "entities":[f"ip:{ip}",f"user:{event['username'] or 'unknown'}"],
                        "evidence":[f"{len(prior)} failed logins from {ip} within {window_minutes} minutes",
                                    f"Subsequent successful login event {event['event_id']}"],
                        "recommendation":"Verify the login with the account owner and review nearby authentication events.",
                        "_sort":event["_dt"]})
                failures=[]
    # Detect one source probing multiple usernames.
    for ip, group in by_ip.items():
        attempts=[e for e in group if e["event_type"] in {"failed_login","authentication_failure","login_failed","invalid_user"}]
        users={e["username"] for e in attempts if e["username"]}
        if len(users)>=3:
            findings.append({
                "rule_id":"TT-002","severity":"MEDIUM","title":"Possible password spraying or username probing",
                "start":attempts[0]["timestamp"],"end":attempts[-1]["timestamp"],
                "entities":[f"ip:{ip}"]+[f"user:{u}" for u in sorted(users)],
                "evidence":[f"{len(attempts)} failed/invalid events involved {len(users)} distinct usernames"],
                "recommendation":"Check whether the source is authorized; inspect authentication policy and rate limiting.",
                "_sort":attempts[-1]["_dt"]})
    # Detect security log clearing.
    for event in events:
        if event["event_type"] in {"security_log_cleared","audit_log_cleared","event_log_cleared"}:
            findings.append({
                "rule_id":"TT-003","severity":"HIGH","title":"Security audit log cleared",
                "start":event["timestamp"],"end":event["timestamp"],
                "entities":[x for x in (f"host:{event['host']}" if event["host"] else "",f"user:{event['username']}" if event["username"] else "") if x],
                "evidence":[f"Event {event['event_id']} reports a security/audit log clear",event["details"] or "No extra details supplied"],
                "recommendation":"Confirm authorization and preserve other available logs for investigation.",
                "_sort":event["_dt"]})
    for finding in findings: finding.pop("_sort",None)
    # Correlation groups are transparent IP-based clusters, not proof of common causation.
    groups=[]
    for ip, group in sorted(by_ip.items()):
        if len(group)>=2:
            groups.append({"key":f"ip:{ip}","event_ids":[e["event_id"] for e in group],
                           "start":group[0]["timestamp"],"end":group[-1]["timestamp"],
                           "event_count":len(group)})
    return {"tool":"ThreatTimeline","version":"1.0.0","mode":"offline_event_correlation",
            "summary":{"events":len(events),"correlation_groups":len(groups),"findings":len(findings),
                       "high":sum(f["severity"]=="HIGH" for f in findings),
                       "medium":sum(f["severity"]=="MEDIUM" for f in findings)},
            "timeline":[{k:v for k,v in e.items() if k!="_dt"} for e in events],
            "correlation_groups":groups,"findings":findings,
            "limitations":["Input data must be normalized JSON; this version does not collect live logs.",
                           "Rules are heuristic and may produce false positives or miss attacks.",
                           "Shared IP addresses can reflect NAT, proxies or shared infrastructure.",
                           "Findings are investigation leads, not proof of compromise."]}
