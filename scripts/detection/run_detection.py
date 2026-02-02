#!/usr/bin/env python3
"""
AnomAI Detection MVP
-------------------
Reads recent CloudTrail-derived events from DynamoDB (anomai_events),
runs simple rule-based checks, and writes detected incidents to out/incidents.json.

Usage examples:
  python scripts/detection/run_detection.py --region us-east-2
  python scripts/detection/run_detection.py --region us-east-2 --limit 2000 --window-minutes 60 --threshold 5 --debug
  python scripts/detection/run_detection.py --region us-east-2 --source file --input data/sample_events.json

Notes:
- Requires AWS creds available in the environment (SSO, env vars, or mounted credentials).
- Default source is DynamoDB scan. You can switch to file mode for offline testing.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3


# ----------------------------
# Time + parsing helpers
# ----------------------------

def parse_iso8601(dt_str: str) -> Optional[datetime]:
    """
    Parse ISO8601 timestamps like:
      2026-02-02T20:05:28Z
      2026-02-02T20:05:28+00:00
    Returns timezone-aware datetime, or None if parsing fails.
    """
    if not dt_str or not isinstance(dt_str, str):
        return None
    s = dt_str.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def in_window(event_time: Optional[datetime], window_start: datetime) -> bool:
    return event_time is not None and event_time >= window_start


def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    if not s or not isinstance(s, str):
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


# ----------------------------
# DynamoDB read
# ----------------------------

def ddb_scan_events(
    region: str,
    table_name: str,
    limit: int,
    debug: bool = False,
) -> List[Dict[str, Any]]:
    """
    Scans DynamoDB table and returns up to `limit` items.
    Uses a Scan with Limit, iterating with LastEvaluatedKey.
    """
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    items: List[Dict[str, Any]] = []
    last_evaluated_key = None

    while len(items) < limit:
        scan_kwargs: Dict[str, Any] = {"Limit": min(500, limit - len(items))}
        if last_evaluated_key:
            scan_kwargs["ExclusiveStartKey"] = last_evaluated_key

        resp = table.scan(**scan_kwargs)
        batch = resp.get("Items", [])
        items.extend(batch)

        last_evaluated_key = resp.get("LastEvaluatedKey")
        if not last_evaluated_key:
            break

    if debug:
        print(f"[DEBUG] DynamoDB scan pulled {len(items)} items from {table_name} (region={region})")

    return items[:limit]


# ----------------------------
# Event normalization
# ----------------------------

def normalize_events(raw_items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Convert DynamoDB items into normalized event dicts:
      - eventTime (string)
      - eventTime_dt (datetime)
      - awsRegion
      - eventName
      - eventSource
      - actor
      - sourceIPAddress
      - errorCode / errorMessage (extracted from embedded event_json if present)
    """
    out: List[Dict[str, Any]] = []

    for it in raw_items:
        event_time = it.get("eventTime") or it.get("event_time")  # be defensive
        dt = parse_iso8601(event_time) if isinstance(event_time, str) else None

        ev_json = it.get("event_json") or it.get("eventJson") or it.get("event")  # defensive
        ev_obj = safe_json_loads(ev_json)

        error_code = None
        error_msg = None
        if ev_obj:
            error_code = ev_obj.get("errorCode")
            error_msg = ev_obj.get("errorMessage")

        out.append({
            "eventTime": event_time,
            "eventTime_dt": dt,
            "awsRegion": it.get("awsRegion") or it.get("aws_region"),
            "eventName": it.get("eventName") or it.get("event_name"),
            "eventSource": it.get("eventSource") or it.get("event_source"),
            "actor": it.get("actor"),
            "sourceIPAddress": it.get("sourceIPAddress") or it.get("source_ip_address"),
            "errorCode": error_code,
            "errorMessage": error_msg,
            "raw": it,
        })

    # Sort ascending by time if possible
    out.sort(key=lambda e: e["eventTime_dt"] or datetime(1970, 1, 1, tzinfo=timezone.utc))
    return out


# ----------------------------
# Rules
# ----------------------------

def rule_access_denied_spike(
    events: List[Dict[str, Any]],
    window_start: datetime,
    threshold: int,
    match_event_name: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Detect AccessDenied/Unauthorized spike (optionally for a specific eventName).
    """

    def is_denied_code(code: str) -> bool:
        c = (code or "").lower()
        return "accessdenied" in c or "unauthorized" in c

    def is_match(e: Dict[str, Any]) -> bool:
        if not in_window(e["eventTime_dt"], window_start):
            return False
        code = e.get("errorCode") or ""
        if not is_denied_code(code):
            return False
        if match_event_name:
            return (e.get("eventName") or "").lower() == match_event_name.lower()
        return True

    denied = [e for e in events if is_match(e)]
    if len(denied) < threshold:
        return None

    by_actor: Dict[str, int] = {}
    by_region: Dict[str, int] = {}
    for e in denied:
        by_actor[e.get("actor") or "unknown"] = by_actor.get(e.get("actor") or "unknown", 0) + 1
        by_region[e.get("awsRegion") or "unknown"] = by_region.get(e.get("awsRegion") or "unknown", 0) + 1

    samples = [{
        "eventTime": e.get("eventTime"),
        "awsRegion": e.get("awsRegion"),
        "eventName": e.get("eventName"),
        "actor": e.get("actor"),
        "errorCode": e.get("errorCode"),
        "errorMessage": e.get("errorMessage"),
    } for e in denied[:5]]

    label = "AccessDenied"
    if match_event_name:
        label = f"AccessDenied({match_event_name})"

    return {
        "type": "access_denied_spike",
        "severity": "high",
        "title": f"{label} spike: {len(denied)} events in window",
        "window_start": window_start.isoformat(),
        "count": len(denied),
        "threshold": threshold,
        "by_actor": by_actor,
        "by_region": by_region,
        "samples": samples,
        "recommendation": "Validate whether this principal should perform these actions. If not, investigate automation/abuse and lock down IAM.",
    }


def rule_invalid_ami_spike(
    events: List[Dict[str, Any]],
    window_start: datetime,
    threshold: int,
) -> Optional[Dict[str, Any]]:
    """
    Detect spike of InvalidAMIID.Malformed errors (RunInstances with fake AMI).
    This matches your generator output.
    """

    def is_match(e: Dict[str, Any]) -> bool:
        if not in_window(e["eventTime_dt"], window_start):
            return False

        code = (e.get("errorCode") or "").lower()
        if code != "invalidamiid.malformed":
            return False

        if (e.get("eventName") or "").lower() != "runinstances":
            return False

        return True

    bad = [e for e in events if is_match(e)]
    if len(bad) < threshold:
        return None

    by_actor: Dict[str, int] = {}
    by_region: Dict[str, int] = {}
    for e in bad:
        by_actor[e.get("actor") or "unknown"] = by_actor.get(e.get("actor") or "unknown", 0) + 1
        by_region[e.get("awsRegion") or "unknown"] = by_region.get(e.get("awsRegion") or "unknown", 0) + 1

    samples = [{
        "eventTime": e.get("eventTime"),
        "awsRegion": e.get("awsRegion"),
        "eventName": e.get("eventName"),
        "actor": e.get("actor"),
        "errorCode": e.get("errorCode"),
        "errorMessage": e.get("errorMessage"),
    } for e in bad[:5]]

    return {
        "type": "invalid_ami_spike",
        "severity": "medium",
        "title": f"InvalidAMIID.Malformed spike: {len(bad)} events in window",
        "window_start": window_start.isoformat(),
        "count": len(bad),
        "threshold": threshold,
        "by_actor": by_actor,
        "by_region": by_region,
        "samples": samples,
        "recommendation": "Check for broken automation or suspicious EC2 launch attempts using invalid AMIs.",
    }


def rule_new_region_seen(
    events: List[Dict[str, Any]],
    window_start: datetime,
    baseline_regions: List[str],
) -> Optional[Dict[str, Any]]:
    """
    Detect if any events within the window are from regions not in the baseline list.
    Baseline can be passed via CLI, e.g.:
      --baseline-regions us-east-2,us-east-1
    """

    baseline = set([r.strip() for r in baseline_regions if r and r.strip()])
    if not baseline:
        return None

    recent = [e for e in events if in_window(e["eventTime_dt"], window_start)]
    new_regions = sorted({(e.get("awsRegion") or "unknown") for e in recent if (e.get("awsRegion") or "unknown") not in baseline})

    if not new_regions:
        return None

    samples = [{
        "eventTime": e.get("eventTime"),
        "awsRegion": e.get("awsRegion"),
        "eventName": e.get("eventName"),
        "actor": e.get("actor"),
        "eventSource": e.get("eventSource"),
    } for e in recent if (e.get("awsRegion") or "unknown") in new_regions][:5]

    return {
        "type": "new_region_activity",
        "severity": "medium",
        "title": f"New region(s) seen in window: {', '.join(new_regions)}",
        "window_start": window_start.isoformat(),
        "new_regions": new_regions,
        "baseline_regions": sorted(list(baseline)),
        "samples": samples,
        "recommendation": "Confirm these regions are expected. If not, check for compromised credentials or unexpected automation.",
    }


# ----------------------------
# Debug summaries
# ----------------------------

def summarize_debug(events: List[Dict[str, Any]], window_start: datetime) -> None:
    times = [e["eventTime_dt"] for e in events if e.get("eventTime_dt")]
    if times:
        print(f"[DEBUG] eventTime range in scanned set: oldest={min(times).isoformat()} newest={max(times).isoformat()}")
    print(f"[DEBUG] window_start={window_start.isoformat()}")

    err = [e for e in events if (e.get("errorCode") or "").strip()]
    denied = [e for e in err if "accessdenied" in (e.get("errorCode") or "").lower() or "unauthorized" in (e.get("errorCode") or "").lower()]
    print(f"[DEBUG] events with any errorCode (from event_json): {len(err)} / {len(events)}")
    print(f"[DEBUG] denied-like errorCode count: {len(denied)}")

    # regions breakdown (all scanned, not just window)
    region_counts: Dict[str, int] = {}
    for e in events:
        r = e.get("awsRegion") or "unknown"
        region_counts[r] = region_counts.get(r, 0) + 1
    top = sorted(region_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    print(f"[DEBUG] top regions in scanned set: {top}")


# ----------------------------
# File read mode
# ----------------------------

def load_events_from_file(path: str, debug: bool = False) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)

    # Allow either:
    # 1) a raw list of events
    # 2) an object with {"events": [...]}
    if isinstance(obj, list):
        raw_items = obj
    elif isinstance(obj, dict) and isinstance(obj.get("events"), list):
        raw_items = obj["events"]
    else:
        raise ValueError("Input file format not recognized. Expected a list or {'events': [...]}.")

    if debug:
        print(f"[DEBUG] Loaded {len(raw_items)} raw items from file: {path}")

    return raw_items


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AnomAI detection rules and write out/incidents.json",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--region", required=True, help="AWS region for DynamoDB access, e.g. us-east-2")
    parser.add_argument("--table", default="anomai_events", help="DynamoDB table name to scan")
    parser.add_argument("--limit", type=int, default=1000, help="How many events to scan/load")
    parser.add_argument("--window-minutes", type=int, default=30, help="Time window size in minutes")
    parser.add_argument("--threshold", type=int, default=5, help="Minimum count to trigger spike incidents")
    parser.add_argument("--source", choices=["dynamodb", "file"], default="dynamodb", help="Event source")
    parser.add_argument("--input", default="data/sample_events.json", help="File input path if --source file")
    parser.add_argument("--baseline-regions", default="", help="Comma-separated baseline regions for new-region rule")
    parser.add_argument("--out", default="out/incidents.json", help="Output JSON path")
    parser.add_argument("--debug", action="store_true", help="Print debug info")

    args = parser.parse_args()

    # Ensure output dir exists
    out_dir = os.path.dirname(args.out) or "."
    os.makedirs(out_dir, exist_ok=True)

    # Load raw events
    if args.source == "file":
        raw_items = load_events_from_file(args.input, debug=args.debug)[: args.limit]
        source_label = "file"
        source_meta = {"input": args.input}
    else:
        raw_items = ddb_scan_events(args.region, args.table, args.limit, debug=args.debug)
        source_label = "dynamodb_scan"
        source_meta = {"table": args.table}

    # Normalize
    events = normalize_events(raw_items)

    # Window start
    now = utc_now()
    window_start = now - timedelta(minutes=args.window_minutes)

    if args.debug:
        summarize_debug(events, window_start)

    # Run rules
    incidents: List[Dict[str, Any]] = []

    # Rule 1: AccessDenied spike (CreateUser only — matches your generator)
    inc1 = rule_access_denied_spike(events, window_start, args.threshold, match_event_name="CreateUser")
    if inc1:
        incidents.append(inc1)

    # Rule 2: Invalid AMI spike (RunInstances + InvalidAMIID.Malformed)
    inc2 = rule_invalid_ami_spike(events, window_start, args.threshold)
    if inc2:
        incidents.append(inc2)

    # Rule 3: New region activity (optional baseline; if no baseline provided, it won't trigger)
    baseline_regions = [r.strip() for r in args.baseline_regions.split(",") if r.strip()]
    inc3 = rule_new_region_seen(events, window_start, baseline_regions)
    if inc3:
        incidents.append(inc3)

    # Write output
    output = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "source": source_label,
        "region": args.region,
        **source_meta,
        "events_scanned": len(events),
        "window_minutes": args.window_minutes,
        "threshold": args.threshold,
        "incident_count": len(incidents),
        "incidents": incidents,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"[OK] Scanned {len(events)} events → Detected {len(incidents)} incidents → Wrote {args.out}")


if __name__ == "__main__":
    main()