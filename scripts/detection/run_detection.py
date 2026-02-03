#!/usr/bin/env python3
"""
AnomAI Detection (Easy Mode)
===========================

Goal: one command, works every time.
- Reads CloudTrail-derived events from DynamoDB (using day_bucket)
- Normalizes events
- Anchors detection window to the NEWEST event in DynamoDB (avoids ingestion delay issues)
- Auto-picks thresholds (no manual tuning needed)
- Writes out/incidents.json + prints a short console summary

Run:
  ./run_detection.py --region us-east-2
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr


# -------------------------
# Time utils
# -------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def parse_iso8601(s: Any) -> Optional[datetime]:
    if not isinstance(s, str) or not s.strip():
        return None
    s = s.strip()
    try:
        if s.endswith("Z"):
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        return datetime.fromisoformat(s)
    except Exception:
        return None

def day_bucket_from_dt(dt: datetime) -> str:
    # YYYY-MM-DD
    return dt.date().isoformat()

def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return json.loads(s)
    except Exception:
        return None

def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

def is_in_window(t: Optional[datetime], window_start: datetime, window_end: datetime) -> bool:
    return t is not None and (window_start <= t <= window_end)


# -------------------------
# Normalized event
# -------------------------

@dataclass
class Event:
    event_time_str: str
    event_time: Optional[datetime]
    day_bucket: str
    aws_region: str
    event_name: str
    event_source: str
    actor: str
    source_ip: str
    error_code: str
    error_message: str
    raw: Dict[str, Any]


def normalize_raw_items(raw_items: List[Dict[str, Any]]) -> List[Event]:
    events: List[Event] = []

    for it in raw_items:
        event_time_str = it.get("eventTime") or ""
        event_time = parse_iso8601(event_time_str)

        # day_bucket: prefer stored value, else derive
        day_bucket = it.get("day_bucket") or (day_bucket_from_dt(event_time) if event_time else "")

        aws_region = it.get("awsRegion") or "unknown"
        event_name = it.get("eventName") or "unknown"
        event_source = it.get("eventSource") or "unknown"
        actor = it.get("actor") or "unknown"
        source_ip = it.get("sourceIPAddress") or "unknown"

        ev_obj = safe_json_loads(it.get("event_json") or "")
        error_code = ""
        error_message = ""
        if ev_obj:
            error_code = str(ev_obj.get("errorCode") or "")
            error_message = str(ev_obj.get("errorMessage") or "")

        events.append(Event(
            event_time_str=str(event_time_str),
            event_time=event_time,
            day_bucket=str(day_bucket),
            aws_region=str(aws_region),
            event_name=str(event_name),
            event_source=str(event_source),
            actor=str(actor),
            source_ip=str(source_ip),
            error_code=error_code,
            error_message=error_message,
            raw=it,
        ))

    # sort newest -> oldest (for easier “latest” behavior)
    events.sort(key=lambda e: e.event_time or datetime(1970, 1, 1, tzinfo=timezone.utc), reverse=True)
    return events


# -------------------------
# DynamoDB loading (day_bucket scan)
# -------------------------

def ddb_scan_day_bucket(
    *,
    region: str,
    table_name: str,
    lookback_days: int,
    max_events: int,
    debug: bool,
) -> List[Dict[str, Any]]:
    """
    Scan and keep only items where day_bucket is in [today-lookback_days .. today].
    Then return most recent up to max_events (still a scan, but filtered).
    """
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    now = utc_now()
    start_day = day_bucket_from_dt(now - timedelta(days=lookback_days))
    end_day = day_bucket_from_dt(now)

    # We scan pages and keep items in range.
    items_kept: List[Dict[str, Any]] = []
    last_key = None
    page = 0

    # Scan in chunks (DynamoDB scan is not ordered)
    while True:
        page += 1
        kwargs: Dict[str, Any] = {"Limit": 500}

        # FilterExpression (server-side) to reduce returned data
        kwargs["FilterExpression"] = Attr("day_bucket").between(start_day, end_day)

        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = table.scan(**kwargs)
        got = resp.get("Items", [])
        items_kept.extend(got)

        if debug:
            print(f"[DEBUG] scan page={page} got={len(got)} total_kept={len(items_kept)}")

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    # We only want newest max_events, but scan returns unsorted.
    # Sort by eventTime string (ISO) descending; missing times sink to bottom.
    def keyfunc(x: Dict[str, Any]) -> str:
        return str(x.get("eventTime") or "")

    items_kept.sort(key=keyfunc, reverse=True)
    items_kept = items_kept[:max_events]

    if debug:
        rng = f"{start_day}..{end_day}"
        print(f"[DEBUG] DynamoDB day_bucket scan: table={table_name} region={region} items_received={len(items_kept)} range={rng}")

    return items_kept


# -------------------------
# Auto thresholds (no user knobs)
# -------------------------

def auto_thresholds(events_in_window: int) -> Dict[str, int]:
    """
    Pick thresholds that scale with volume but stay sane for small windows.
    """
    denied = max(5, int(events_in_window * 0.03))          # 3% of window volume or 5
    invalid_ami = 1                                        # any invalid AMI is interesting
    iam = max(3, int(events_in_window * 0.005))            # 0.5% or 3
    signin = 3                                             # basic
    burst = max(300, int(events_in_window * 0.25))         # 25% of total window or 300
    return {
        "denied_threshold": denied,
        "invalid_ami_threshold": invalid_ami,
        "iam_threshold": iam,
        "signin_threshold": signin,
        "burst_threshold": burst,
    }


# -------------------------
# Incident helpers
# -------------------------

def top_n_counts(values: List[str], n: int = 5) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for v in values:
        c[v] = c.get(v, 0) + 1
    return dict(sorted(c.items(), key=lambda x: x[1], reverse=True)[:n])

def sample_events(events: List[Event], max_samples: int = 6) -> List[Dict[str, Any]]:
    out = []
    for e in events[:max_samples]:
        out.append({
            "eventTime": e.event_time_str,
            "day_bucket": e.day_bucket,
            "awsRegion": e.aws_region,
            "eventName": e.event_name,
            "eventSource": e.event_source,
            "actor": e.actor,
            "sourceIPAddress": e.source_ip,
            "errorCode": e.error_code,
            "errorMessage": (e.error_message[:220] + "…") if len(e.error_message) > 220 else e.error_message,
        })
    return out

def severity_from_count(count: int, *, high: int, medium: int) -> str:
    if count >= high:
        return "high"
    if count >= medium:
        return "medium"
    return "low"


# -------------------------
# Detectors
# -------------------------

def detect_access_denied_spike(events: List[Event], window_start: datetime, window_end: datetime, threshold: int) -> Optional[Dict[str, Any]]:
    recent = [e for e in events if is_in_window(e.event_time, window_start, window_end)]
    hits = [e for e in recent if ("accessdenied" in e.error_code.lower() or "unauthorized" in e.error_code.lower())]

    if len(hits) < threshold:
        return None

    sev = severity_from_count(len(hits), high=max(20, threshold * 3), medium=max(10, threshold * 2))
    return {
        "type": "access_denied_spike",
        "severity": sev,
        "title": f"Access denied spike: {len(hits)} denied errors in window",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "If unexpected: investigate the principal + source IP, and check for broken automation or credential misuse.",
    }

def detect_invalid_ami(events: List[Event], window_start: datetime, window_end: datetime, threshold: int) -> Optional[Dict[str, Any]]:
    recent = [e for e in events if is_in_window(e.event_time, window_start, window_end)]
    hits = [e for e in recent if e.event_name.lower() == "runinstances" and e.error_code.lower() == "invalidamiid.malformed"]

    if len(hits) < threshold:
        return None

    sev = "medium" if len(hits) < 5 else "high"
    return {
        "type": "invalid_ami_attempts",
        "severity": sev,
        "title": f"Invalid AMI attempts: {len(hits)} RunInstances InvalidAMIID.Malformed",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "Could be broken automation or probing. Verify who ran it and why.",
    }

def detect_sensitive_iam_ops(events: List[Event], window_start: datetime, window_end: datetime, threshold: int) -> Optional[Dict[str, Any]]:
    sensitive = {
        "createuser", "createaccesskey", "putuserpolicy", "attachuserpolicy",
        "attachgrouppolicy", "attachrolepolicy", "addusertogroup",
        "updateloginprofile", "createpolicy", "createpolicyversion",
        "setdefaultpolicyversion", "passrole",
    }
    recent = [e for e in events if is_in_window(e.event_time, window_start, window_end)]
    hits = [e for e in recent if e.event_name.lower() in sensitive]

    if len(hits) < threshold:
        return None

    sev = severity_from_count(len(hits), high=max(10, threshold * 3), medium=max(5, threshold * 2))
    return {
        "type": "sensitive_iam_activity",
        "severity": sev,
        "title": f"Sensitive IAM activity: {len(hits)} ops in window",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "count": len(hits),
        "threshold": threshold,
        "by_actor": top_n_counts([e.actor for e in hits]),
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "If unexpected: investigate privilege escalation or compromised admin credentials.",
    }

def detect_api_burst_by_actor(events: List[Event], window_start: datetime, window_end: datetime, threshold: int) -> Optional[Dict[str, Any]]:
    recent = [e for e in events if is_in_window(e.event_time, window_start, window_end)]
    if not recent:
        return None

    counts: Dict[str, int] = {}
    for e in recent:
        counts[e.actor] = counts.get(e.actor, 0) + 1

    actor, count = max(counts.items(), key=lambda x: x[1])
    if count < threshold:
        return None

    hits = [e for e in recent if e.actor == actor]
    sev = severity_from_count(count, high=max(800, threshold * 3), medium=max(300, threshold * 2))
    return {
        "type": "api_burst",
        "severity": sev,
        "title": f"API burst: {actor} made {count} calls in window",
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "count": count,
        "threshold": threshold,
        "by_region": top_n_counts([e.aws_region for e in hits]),
        "by_eventName": top_n_counts([e.event_name for e in hits]),
        "samples": sample_events(hits),
        "recommendation": "If not expected automation: investigate for scripted abuse and lock down credentials.",
    }


# -------------------------
# Console summary (SOC vibe)
# -------------------------

def print_soc_summary(*, events_kept: int, newest: Optional[str], oldest: Optional[str],
                      window_start: datetime, window_end: datetime,
                      incidents: List[Dict[str, Any]]) -> None:
    print("\n=== AnomAI Detection Summary ===")
    print(f"events_kept: {events_kept}")
    if newest and oldest:
        print(f"time_range: newest={newest} oldest={oldest}")
    print(f"detect_window: {window_start.isoformat()} .. {window_end.isoformat()}")
    print(f"incidents: {len(incidents)}")

    if incidents:
        print("\nINCIDENTS:")
        for i, inc in enumerate(incidents, 1):
            print(f"{i}. [{inc['severity'].upper()}] {inc['type']} — {inc['title']}")
    print("")


# -------------------------
# Main
# -------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="AnomAI Detection (easy mode). One command, auto thresholds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--region", required=True, help="AWS region for DynamoDB access (e.g. us-east-2)")
    parser.add_argument("--table", default="anomai_events", help="DynamoDB table name")
    parser.add_argument("--lookback-days", type=int, default=30, help="How far back to look using day_bucket")
    parser.add_argument("--max-events", type=int, default=5000, help="Keep at most N most recent events")
    parser.add_argument("--detect-window-minutes", type=int, default=10, help="Detection window length (anchored to newest event)")
    parser.add_argument("--out", default="out/incidents.json", help="Output JSON path")
    parser.add_argument("--debug", action="store_true", help="Print debug info")

    args = parser.parse_args()
    ensure_parent_dir(args.out)

    raw_items = ddb_scan_day_bucket(
        region=args.region,
        table_name=args.table,
        lookback_days=args.lookback_days,
        max_events=args.max_events,
        debug=args.debug,
    )

    events = normalize_raw_items(raw_items)

    # If table is empty or timestamps missing
    if not events or not events[0].event_time:
        output = {
            "generated_at": utc_now().isoformat().replace("+00:00", "Z"),
            "source": "dynamodb_day_bucket_scan",
            "region": args.region,
            "table": args.table,
            "lookback_days": args.lookback_days,
            "max_events": args.max_events,
            "detect_window_minutes": args.detect_window_minutes,
            "events_kept": len(events),
            "incident_count": 0,
            "incidents": [],
            "note": "No events with valid eventTime found.",
        }
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)
        print(f"[OK] Kept {len(events)} events → Detected 0 incidents → Wrote {args.out}")
        return

    newest_event_time = events[0].event_time
    window_end = newest_event_time
    window_start = newest_event_time - timedelta(minutes=args.detect_window_minutes)

    recent = [e for e in events if is_in_window(e.event_time, window_start, window_end)]
    thresholds = auto_thresholds(len(recent))

    if args.debug:
        newest_str = events[0].event_time_str
        oldest_str = events[-1].event_time_str if events[-1].event_time_str else ""
        print(f"[DEBUG] newest_kept={len(events)} time_range(newest..oldest)={newest_str} .. {oldest_str}")
        print(f"[DEBUG] kept_events={len(events)} time_range newest={events[0].event_time} oldest={events[-1].event_time}")
        print(f"[DEBUG] detect_window_start={window_start.isoformat()}")
        print(f"[DEBUG] detect_window_end={window_end.isoformat()}")
        print(f"[DEBUG] events_in_detect_window={len(recent)}")
        denied_like = sum(1 for e in events if e.error_code and ("accessdenied" in e.error_code.lower() or "unauthorized" in e.error_code.lower()))
        print(f"[DEBUG] denied_like_total={denied_like}")
        print(f"[DEBUG] top_regions={list(top_n_counts([e.aws_region for e in events], n=6).items())}")
        print(f"[DEBUG] auto_thresholds={thresholds}")

    incidents: List[Dict[str, Any]] = []

    inc = detect_access_denied_spike(events, window_start, window_end, thresholds["denied_threshold"])
    if inc:
        incidents.append(inc)

    inc = detect_invalid_ami(events, window_start, window_end, thresholds["invalid_ami_threshold"])
    if inc:
        incidents.append(inc)

    inc = detect_sensitive_iam_ops(events, window_start, window_end, thresholds["iam_threshold"])
    if inc:
        incidents.append(inc)

    inc = detect_api_burst_by_actor(events, window_start, window_end, thresholds["burst_threshold"])
    if inc:
        incidents.append(inc)

    output = {
        "generated_at": utc_now().isoformat().replace("+00:00", "Z"),
        "source": "dynamodb_day_bucket_scan",
        "region": args.region,
        "table": args.table,
        "lookback_days": args.lookback_days,
        "max_events": args.max_events,
        "detect_window_minutes": args.detect_window_minutes,
        "detect_window": {
            "start": window_start.isoformat().replace("+00:00", "Z"),
            "end": window_end.isoformat().replace("+00:00", "Z"),
            "anchored_to": "newest_event_in_dynamodb",
        },
        "events_kept": len(events),
        "events_in_detect_window": len(recent),
        "thresholds_auto": thresholds,
        "incident_count": len(incidents),
        "incidents": incidents,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    newest_str = events[0].event_time_str
    oldest_str = events[-1].event_time_str
    print_soc_summary(
        events_kept=len(events),
        newest=newest_str,
        oldest=oldest_str,
        window_start=window_start,
        window_end=window_end,
        incidents=incidents,
    )

    print(f"[OK] Kept {len(events)} events → Detected {len(incidents)} incidents → Wrote {args.out}")


if __name__ == "__main__":
    main()
