#!/usr/bin/env python3
"""
AnomAI Detection MVP (Stronger Version)
======================================

What this script does:
- Loads CloudTrail-derived events from DynamoDB (anomai_events) OR a local JSON file
- Normalizes event fields into a consistent shape
- Runs multiple rule-based detectors to produce incidents
- Writes results to out/incidents.json

Why:
This is the "middle layer" between:
  (1) events being ingested into DynamoDB
  (2) UI + AI explanation later

Usage examples:
---------------
# DynamoDB (recommended for real testing)
python scripts/detection/run_detection.py --region us-east-2

# Scan more events + use larger time window
python scripts/detection/run_detection.py --region us-east-2 --limit 5000 --window-minutes 120 --debug

# File mode (offline)
python scripts/detection/run_detection.py --region us-east-2 --source file --input data/sample_events.json

# Provide baseline regions (so new-region detection can trigger)
python scripts/detection/run_detection.py --region us-east-2 --baseline-regions us-east-2,us-east-1

Outputs:
--------
Creates out/incidents.json with:
- summary
- incidents[] each with type/title/severity/evidence/samples/recommendation
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3


# -------------------------
# Utilities: time + parsing
# -------------------------

def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


def parse_iso8601(s: Any) -> Optional[datetime]:
    """
    Parse ISO timestamps like:
      2026-02-02T20:05:28Z
      2026-02-02T20:05:28+00:00
    Return timezone-aware datetime, or None if invalid.
    """
    if not isinstance(s, str) or not s.strip():
        return None
    s = s.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None


def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    """Try to json.loads a string; return None on failure."""
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def ensure_parent_dir(path: str) -> None:
    """Create parent folder for a file path if needed."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def is_in_window(t: Optional[datetime], window_start: datetime) -> bool:
    """True if timestamp exists and is within [window_start, now]."""
    return t is not None and t >= window_start


# -------------------------
# Normalized event structure
# -------------------------

@dataclass
class Event:
    """
    Normalized event object used by detectors.
    We keep both parsed fields and the raw DynamoDB record.
    """
    event_time_str: str
    event_time: Optional[datetime]
    aws_region: str
    event_name: str
    event_source: str
    actor: str
    source_ip: str
    error_code: str
    error_message: str
    raw: Dict[str, Any]


def normalize_raw_items(raw_items: List[Dict[str, Any]]) -> List[Event]:
    """
    Convert DynamoDB items (or file events shaped similarly) into normalized Events.
    Your table columns: accountId, actor, awsRegion, eventName, eventSource, eventTime, event_json, ...
    We extract errorCode/errorMessage from embedded event_json.
    """
    events: List[Event] = []

    for it in raw_items:
        # Preferred fields (match your schema), plus defensive fallbacks
        event_time_str = it.get("eventTime") or it.get("event_time") or ""
        event_time = parse_iso8601(event_time_str)

        aws_region = it.get("awsRegion") or it.get("aws_region") or "unknown"
        event_name = it.get("eventName") or it.get("event_name") or "unknown"
        event_source = it.get("eventSource") or it.get("event_source") or "unknown"
        actor = it.get("actor") or "unknown"
        source_ip = it.get("sourceIPAddress") or it.get("source_ip_address") or "unknown"

        # CloudTrail JSON is stored as a string in event_json
        ev_obj = safe_json_loads(it.get("event_json") or it.get("eventJson") or it.get("event") or "")
        error_code = ""
        error_message = ""
        if ev_obj:
            error_code = str(ev_obj.get("errorCode") or "")
            error_message = str(ev_obj.get("errorMessage") or "")

        events.append(Event(
            event_time_str=event_time_str,
            event_time=event_time,
            aws_region=str(aws_region),
            event_name=str(event_name),
            event_source=str(event_source),
            actor=str(actor),
            source_ip=str(source_ip),
            error_code=error_code,
            error_message=error_message,
            raw=it,
        ))

    # Sort by time ascending for stable logic + nicer debug
    events.sort(key=lambda e: e.event_time or datetime(1970, 1, 1, tzinfo=timezone.utc))
    return events


# -------------------------
# DynamoDB + file loading
# -------------------------

def ddb_scan(region: str, table_name: str, limit: int, debug: bool) -> List[Dict[str, Any]]:
    """
    Scan DynamoDB table and return up to `limit` items.
    - Scan is simple & reliable for MVP (not optimal for huge tables).
    """
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    items: List[Dict[str, Any]] = []
    last_key = None

    while len(items) < limit:
        kwargs: Dict[str, Any] = {"Limit": min(500, limit - len(items))}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    if debug:
        print(f"[DEBUG] DynamoDB scan: table={table_name} region={region} pulled={len(items)}")
    return items[:limit]


def load_from_file(path: str) -> List[Dict[str, Any]]:
    """
    Accept either:
      - a list of event dicts
      - an object like {"events": [...]}
    """
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict) and isinstance(obj.get("events"), list):
        return obj["events"]

    raise ValueError("Input file must be a list of events or {'events': [...]}.")


# -------------------------
# Incident helper builders
# -------------------------

def severity_from_count(count: int, high: int, medium: int) -> str:
    """
    Basic severity scaling:
      count >= high -> high
      count >= medium -> medium
      else -> low
    """
    if count >= high:
        return "high"
    if count >= medium:
        return "medium"
    return "low"


def top_n_counts(values: List[str], n: int = 5) -> Dict[str, int]:
    """Return top-N counts from a list."""
    c: Dict[str, int] = {}
    for v in values:
        c[v] = c.get(v, 0) + 1
    return dict(sorted(c.items(), key=lambda x: x[1], reverse=True)[:n])


def sample_events(events: List[Event], max_samples: int = 6) -> List[Dict[str, Any]]:
    """Return compact samples for incidents."""
    out = []
    for e in events[:max_samples]:
        out.append({
            "eventTime": e.event_time_str,
            "awsRegion": e.aws_region,
            "eventName": e.event_name,
            "eventSource": e.event_source,
            "actor": e.actor,
            "sourceIPAddress": e.source_ip,
            "errorCode": e.error_code,
            "errorMessage": (e.error_message[:220] + "…") if len(e.error_message) > 220 else e.error_message,
        })
    return out


# -------------------------
# Detectors (multiple incidents)
# -------------------------

def detect_access_denied_spike(
    events: List[Event],
    window_start: datetime,
    threshold: int,
) -> Optional[Dict[str, Any]]:
    """
    Detect AccessDenied/Unauthorized spikes (any API).
    Good for your generator's AccessDenied scenario.
    """
    def denied(e: Event) -> bool:
        c = e.error_code.lower()
        return ("accessdenied" in c) or ("unauthorized" in c)

    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    hits = [e for e in recent if denied(e)]

    if len(hits) < threshold:
        return None

    sev = severity_from_count(len(hits), high=20, medium=10)

    return {
        "type": "access_denied_spike",
        "severity": sev,
        "title": f"Denied spike: {len(hits)} AccessDenied/Unauthorized errors in window",
        "window_start": window_start.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "Confirm the failing principal is expected. If not, investigate credential misuse or broken automation and tighten IAM policies.",
    }


def detect_invalid_ami_spike(
    events: List[Event],
    window_start: datetime,
    threshold: int,
) -> Optional[Dict[str, Any]]:
    """
    Detect invalid AMI attempts:
      eventName=RunInstances AND errorCode=InvalidAMIID.Malformed
    Matches your generator output.
    """
    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    hits = [
        e for e in recent
        if e.event_name.lower() == "runinstances"
        and e.error_code.lower() == "invalidamiid.malformed"
    ]

    if len(hits) < threshold:
        return None

    sev = severity_from_count(len(hits), high=15, medium=8)

    return {
        "type": "invalid_ami_spike",
        "severity": sev,
        "title": f"EC2 invalid AMI attempts: {len(hits)} InvalidAMIID.Malformed in window",
        "window_start": window_start.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "Could be broken automation or probing. Verify automation scripts and consider alerting if unexpected principals attempt EC2 launches.",
    }


def detect_new_region_activity(
    events: List[Event],
    window_start: datetime,
    baseline_regions: List[str],
) -> Optional[Dict[str, Any]]:
    """
    Detect any activity in regions not in baseline list.
    You provide baseline regions via --baseline-regions.
    """
    baseline = {r.strip() for r in baseline_regions if r.strip()}
    if not baseline:
        return None  # no baseline => we can't claim "new"

    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    regions_seen = sorted({e.aws_region for e in recent})
    new_regions = [r for r in regions_seen if r not in baseline]

    if not new_regions:
        return None

    # collect samples only from new regions
    hits = [e for e in recent if e.aws_region in new_regions]
    sev = "medium" if len(new_regions) <= 2 else "high"

    return {
        "type": "new_region_activity",
        "severity": sev,
        "title": f"New region activity detected: {', '.join(new_regions)}",
        "window_start": window_start.isoformat(),
        "baseline_regions": sorted(baseline),
        "new_regions": new_regions,
        "count": len(hits),
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "If these regions are not expected for your environment, investigate potential credential compromise and restrict regions with SCPs or IAM conditions.",
    }


def detect_api_burst_by_actor(
    events: List[Event],
    window_start: datetime,
    burst_threshold: int,
) -> Optional[Dict[str, Any]]:
    """
    Detect burst of API activity by a single actor in the window.
    This catches your 'burst api calls' scenario even if they succeed.
    """
    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    if not recent:
        return None

    # Count by actor (all API calls)
    counts: Dict[str, int] = {}
    for e in recent:
        counts[e.actor] = counts.get(e.actor, 0) + 1

    # Find the biggest spike actor
    actor, count = max(counts.items(), key=lambda x: x[1])

    if count < burst_threshold:
        return None

    actor_events = [e for e in recent if e.actor == actor]
    sev = severity_from_count(count, high=800, medium=300)

    return {
        "type": "api_call_burst",
        "severity": sev,
        "title": f"API burst: actor '{actor}' made {count} calls in window",
        "window_start": window_start.isoformat(),
        "count": count,
        "threshold": burst_threshold,
        "by_region": top_n_counts([e.aws_region for e in actor_events]),
        "by_eventName": top_n_counts([e.event_name for e in actor_events]),
        "samples": sample_events(actor_events),
        "recommendation": "Confirm if this is expected automation. If not, investigate for scripted abuse or compromised credentials and consider throttling/guardrails.",
    }


def detect_suspicious_iam_ops(
    events: List[Event],
    window_start: datetime,
    threshold: int,
) -> Optional[Dict[str, Any]]:
    """
    Detect spikes of sensitive IAM operations:
      CreateUser, CreateAccessKey, PutUserPolicy, AttachUserPolicy, AddUserToGroup, UpdateLoginProfile, etc.
    Great for "mixed events" testing.
    """
    sensitive = {
        "createuser",
        "createaccesskey",
        "putuserpolicy",
        "attachuserpolicy",
        "attachgrouppolicy",
        "attachrolepolicy",
        "addusertogroup",
        "updateloginprofile",
        "createpolicy",
        "createpolicyversion",
        "setdefaultpolicyversion",
        "passrole",
    }

    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    hits = [e for e in recent if e.event_name.lower() in sensitive]

    if len(hits) < threshold:
        return None

    sev = severity_from_count(len(hits), high=25, medium=10)

    return {
        "type": "suspicious_iam_activity",
        "severity": sev,
        "title": f"Sensitive IAM activity spike: {len(hits)} ops in window",
        "window_start": window_start.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "Review IAM changes for legitimacy. If unexpected, check CloudTrail for surrounding actions and lock down privilege escalation paths.",
    }


# -------------------------
# Debug helpers
# -------------------------

def debug_summary(events: List[Event], window_start: datetime) -> None:
    """Print useful debug signals to understand why incidents did/didn't trigger."""
    times = [e.event_time for e in events if e.event_time]
    if times:
        print(f"[DEBUG] eventTime range: oldest={min(times).isoformat()} newest={max(times).isoformat()}")
    print(f"[DEBUG] window_start={window_start.isoformat()} (window_minutes from args)")

    recent = [e for e in events if is_in_window(e.event_time, window_start)]
    print(f"[DEBUG] events in window: {len(recent)} / total scanned: {len(events)}")

    err = [e for e in events if e.error_code]
    denied = [e for e in err if ("accessdenied" in e.error_code.lower() or "unauthorized" in e.error_code.lower())]
    print(f"[DEBUG] events with errorCode: {len(err)} / {len(events)}")
    print(f"[DEBUG] denied-like errors: {len(denied)}")

    regions = [e.aws_region for e in events]
    print(f"[DEBUG] top regions scanned: {list(top_n_counts(regions, n=8).items())}")


# -------------------------
# Main
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AnomAI rule-based detection and write out/incidents.json",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Required
    parser.add_argument("--region", required=True, help="AWS region for DynamoDB access (e.g. us-east-2)")

    # Source selection
    parser.add_argument("--source", choices=["dynamodb", "file"], default="dynamodb", help="Where to load events from")
    parser.add_argument("--table", default="anomai_events", help="DynamoDB table name (when source=dynamodb)")
    parser.add_argument("--input", default="data/sample_events.json", help="Input JSON file (when source=file)")

    # Volume + windowing
    parser.add_argument("--limit", type=int, default=2000, help="How many events to scan/load")
    parser.add_argument("--window-minutes", type=int, default=60, help="Time window for detection")
    parser.add_argument("--threshold", type=int, default=5, help="Generic threshold for spike detectors")

    # Specific detector thresholds (so your tests are easier)
    parser.add_argument("--burst-threshold", type=int, default=300, help="Actor API call burst threshold in window")
    parser.add_argument("--iam-threshold", type=int, default=10, help="Sensitive IAM ops threshold in window")

    # Baseline list for new-region detection
    parser.add_argument("--baseline-regions", default="", help="Comma-separated baseline regions (for new-region rule)")

    # Output + debug
    parser.add_argument("--out", default="out/incidents.json", help="Output JSON path")
    parser.add_argument("--debug", action="store_true", help="Print debug stats")

    args = parser.parse_args()

    ensure_parent_dir(args.out)

    # 1) Load raw events
    if args.source == "file":
        raw_items = load_from_file(args.input)[: args.limit]
        source_label = "file"
        source_meta = {"input": args.input}
    else:
        raw_items = ddb_scan(args.region, args.table, args.limit, args.debug)
        source_label = "dynamodb_scan"
        source_meta = {"table": args.table}

    # 2) Normalize + sort
    events = normalize_raw_items(raw_items)

    # 3) Compute detection window start time
    now = utc_now()
    window_start = now - timedelta(minutes=args.window_minutes)

    # Optional debug
    if args.debug:
        debug_summary(events, window_start)

    # 4) Run detectors (multi-region by default, because awsRegion comes from each event)
    baseline_regions = [r.strip() for r in args.baseline_regions.split(",") if r.strip()]

    incidents: List[Dict[str, Any]] = []

    inc = detect_access_denied_spike(events, window_start, args.threshold)
    if inc:
        incidents.append(inc)

    inc = detect_invalid_ami_spike(events, window_start, args.threshold)
    if inc:
        incidents.append(inc)

    inc = detect_new_region_activity(events, window_start, baseline_regions)
    if inc:
        incidents.append(inc)

    inc = detect_api_burst_by_actor(events, window_start, args.burst_threshold)
    if inc:
        incidents.append(inc)

    inc = detect_suspicious_iam_ops(events, window_start, args.iam_threshold)
    if inc:
        incidents.append(inc)

    # 5) Write output
    output = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "source": source_label,
        "region": args.region,
        **source_meta,
        "events_scanned": len(events),
        "window_minutes": args.window_minutes,
        "thresholds": {
            "generic_spike": args.threshold,
            "burst_threshold": args.burst_threshold,
            "iam_threshold": args.iam_threshold,
        },
        "baseline_regions": baseline_regions,
        "incident_count": len(incidents),
        "incidents": incidents,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"[OK] Scanned {len(events)} events → Detected {len(incidents)} incidents → Wrote {args.out}")


if __name__ == "__main__":
    main()