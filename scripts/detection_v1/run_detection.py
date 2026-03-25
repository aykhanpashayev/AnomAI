#!/usr/bin/env python3
"""
AnomAI SOC-Style Detection (Easy Mode) — DynamoDB → Incidents
============================================================

Goal (what you asked for):
- You run ONE command (or even no args).
- Script scans your DynamoDB table, looks back ~30 days, and finds incidents
  across ALL events (not just spikes).
- Outputs a clean incident timeline + JSON file.
- On the next run, it marks incidents as "new" if they happened after the last run.

Works with your schema:
PK: event_id
Attrs: eventTime, day_bucket, awsRegion, eventName, eventSource, actor, sourceIPAddress, event_json, ...

Default behavior:
- table: anomai_events
- region: us-east-2 (or AWS_REGION/AWS_DEFAULT_REGION)
- lookback: 30 days
- scans ALL items in that lookback range (your table ~9k items -> fine)
- detection window: 10 minutes (SOC-like short windows for spikes)
- auto-thresholds (no manual thresholds needed)

Run:
  ./scripts/detection/run_detection.py
or:
  ./scripts/detection/run_detection.py --region us-east-2
  ./scripts/detection/run_detection.py --debug

Output:
  out/incidents.json
  out/detection_state.json   (stores watermark so next run can mark new incidents)
"""

from __future__ import annotations

import json
import os
import sys
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr


# ----------------------------
# Defaults (easy for your scope)
# ----------------------------

DEFAULT_REGION = "us-east-2"
DEFAULT_TABLE = "anomai_events"

LOOKBACK_DAYS = 30
DETECT_WINDOW_MINUTES = 10

OUT_PATH = "out/incidents.json"
STATE_PATH = "out/detection_state.json"


# -------------------------
# Small helpers
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


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def human_age(now: datetime, t: datetime) -> str:
    """Return '2m ago', '5h ago', 'yesterday', '6d ago' style strings."""
    delta = now - t
    sec = int(delta.total_seconds())
    if sec < 0:
        sec = abs(sec)
        if sec < 60:
            return f"in {sec}s"
        if sec < 3600:
            return f"in {sec // 60}m"
        if sec < 86400:
            return f"in {sec // 3600}h"
        return f"in {sec // 86400}d"

    if sec < 60:
        return f"{sec}s ago"
    if sec < 3600:
        return f"{sec // 60}m ago"
    if sec < 86400:
        return f"{sec // 3600}h ago"
    days = sec // 86400
    if days == 1:
        return "yesterday"
    return f"{days}d ago"


def minute_bucket(dt: datetime) -> datetime:
    """Floor datetime to the minute."""
    return dt.replace(second=0, microsecond=0)


def get_arg_value(flag: str) -> Optional[str]:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def has_flag(flag: str) -> bool:
    return flag in sys.argv


# -------------------------
# State (watermark + seen incidents)
# -------------------------

def read_state(path: str) -> Dict[str, Any]:
    """Read detection state safely.

    Backwards-compatible:
      - older state files may only contain last_seen_event_time
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj
        return {}
    except Exception:
        return {}


def write_state(path: str, *, last_seen_event_time: str, seen_incident_ids: List[str]) -> None:
    ensure_parent_dir(path)
    obj = {
        "last_seen_event_time": last_seen_event_time,
        "seen_incident_ids": sorted(set(seen_incident_ids)),
        "updated_at": iso_z(utc_now()),
        "schema_version": 2,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def get_state_watermark(state: Dict[str, Any]) -> Optional[str]:
    w = state.get("last_seen_event_time")
    return str(w) if w else None


def get_state_seen_ids(state: Dict[str, Any]) -> List[str]:
    v = state.get("seen_incident_ids")
    if isinstance(v, list):
        return [str(x) for x in v if isinstance(x, (str, int, float))]
    return []


# -------------------------
# Normalized event
# -------------------------

@dataclass
class Event:
    event_id: str
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


def normalize_items(raw_items: List[Dict[str, Any]]) -> List[Event]:
    out: List[Event] = []

    for it in raw_items:
        event_id = str(it.get("event_id") or it.get("eventID") or it.get("id") or "")
        event_time_str = str(it.get("eventTime") or "")
        event_time = parse_iso8601(event_time_str)

        day_bucket_val = it.get("day_bucket") or ""
        day_bucket = str(day_bucket_val) if day_bucket_val else ""
        # If day_bucket missing, compute from eventTime (safe fallback)
        if not day_bucket and event_time:
            day_bucket = event_time.date().isoformat()

        aws_region = str(it.get("awsRegion") or "unknown")
        event_name = str(it.get("eventName") or "unknown")
        event_source = str(it.get("eventSource") or "unknown")
        actor = str(it.get("actor") or "unknown")
        source_ip = str(it.get("sourceIPAddress") or "unknown")

        ev_obj = safe_json_loads(it.get("event_json") or "")
        error_code = ""
        error_message = ""
        if ev_obj:
            error_code = str(ev_obj.get("errorCode") or "")
            error_message = str(ev_obj.get("errorMessage") or "")

        out.append(Event(
            event_id=event_id,
            event_time_str=event_time_str,
            event_time=event_time,
            day_bucket=day_bucket,
            aws_region=aws_region,
            event_name=event_name,
            event_source=event_source,
            actor=actor,
            source_ip=source_ip,
            error_code=error_code,
            error_message=error_message,
            raw=it,
        ))

    out.sort(key=lambda e: e.event_time or datetime(1970, 1, 1, tzinfo=timezone.utc))
    return out


# -------------------------
# DynamoDB scanning
# -------------------------

def resolve_region(passed_region: Optional[str]) -> Optional[str]:
    if passed_region and passed_region.strip():
        return passed_region.strip()

    env_region = (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "").strip()
    if env_region:
        return env_region

    # Try boto3 session default (sometimes set by AWS SDK config)
    try:
        s = boto3.session.Session()
        if s.region_name:
            return s.region_name
    except Exception:
        pass

    # Fall back to our default for your project
    return DEFAULT_REGION


def scan_last_days(table_name: str, region: str, lookback_days: int, max_items: Optional[int], debug: bool) -> List[Dict[str, Any]]:
    """
    Scans ALL items but server-filters to last N days using day_bucket (YYYY-MM-DD).
    For your table size (~9k), this is fine.

    max_items:
      None => no cap (scan everything in lookback range)
      int  => stop after N returned items
    """
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    cutoff_day = (utc_now() - timedelta(days=lookback_days)).date().isoformat()

    items: List[Dict[str, Any]] = []
    last_key = None
    page = 0

    # FilterExpression reduces returned items; Scan still reads behind the scenes,
    # but for your scale it's OK.
    filter_expr = Attr("day_bucket").gte(cutoff_day)

    while True:
        page += 1
        kwargs: Dict[str, Any] = {
            "FilterExpression": filter_expr,
        }
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key

        resp = table.scan(**kwargs)
        got = resp.get("Items", [])
        items.extend(got)

        if debug:
            print(f"[DEBUG] scan page={page} got={len(got)} total_returned={len(items)} cutoff_day={cutoff_day}")

        if max_items is not None and len(items) >= max_items:
            items = items[:max_items]
            break

        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    if debug and items:
        days = [it.get("day_bucket", "") for it in items if it.get("day_bucket")]
        if days:
            print(f"[DEBUG] DynamoDB scan: returned={len(items)} day_bucket_range={min(days)}..{max(days)}")

    return items


# -------------------------
# Counting + auto thresholds
# -------------------------

def count_by(items: List[str]) -> Dict[str, int]:
    m: Dict[str, int] = {}
    for x in items:
        m[x] = m.get(x, 0) + 1
    return dict(sorted(m.items(), key=lambda kv: kv[1], reverse=True))


def top_n(d: Dict[str, int], n: int = 8) -> Dict[str, int]:
    return dict(list(d.items())[:n])


def build_minute_bins(events: List[Event], start: datetime, end: datetime) -> Dict[datetime, List[Event]]:
    """
    Bin events into minute buckets, only within [start, end].
    """
    bins: Dict[datetime, List[Event]] = {}
    for e in events:
        if not e.event_time:
            continue
        if e.event_time < start or e.event_time > end:
            continue
        b = minute_bucket(e.event_time)
        bins.setdefault(b, []).append(e)
    return bins


def compute_baseline_threshold(series: List[int], hard_min: int, multiplier: float = 3.0) -> int:
    """
    Simple "no-math-libs" baseline:
    threshold = max(hard_min, median + multiplier * IQR-ish)

    We avoid fancy stats here to keep it stable and predictable.
    """
    if not series:
        return hard_min
    s = sorted(series)
    n = len(s)
    median = s[n // 2]
    q1 = s[n // 4]
    q3 = s[(3 * n) // 4]
    iqr = max(0, q3 - q1)
    thr = int(median + multiplier * iqr)
    return max(hard_min, thr)


# -------------------------
# Incident builders
# -------------------------

def compact_samples(events: List[Event], max_samples: int = 6) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
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


def stable_hash16(s: str) -> str:
    """Deterministic short hash for IDs."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def incident_primary_key(inc_type: str, evidence: Dict[str, Any]) -> str:
    """Pick a stable discriminator so incident_id is deterministic.

    Prefer the top actor if present.
    """
    if isinstance(evidence, dict):
        by_actor = evidence.get("by_actor")
        if isinstance(by_actor, dict) and by_actor:
            top_actor = next(iter(by_actor.keys()))
            if top_actor:
                return f"actor:{top_actor}"

        peak_actor = evidence.get("peak_actor")
        if isinstance(peak_actor, str) and peak_actor:
            return f"actor:{peak_actor}"

        new_regions = evidence.get("new_regions")
        if isinstance(new_regions, list) and new_regions:
            return "regions:" + ",".join(sorted([str(r) for r in new_regions]))

    return "unknown"


def make_incident(
    *,
    inc_type: str,
    severity: str,
    title: str,
    first_seen: datetime,
    last_seen: datetime,
    count: int,
    evidence: Dict[str, Any],
    samples: List[Dict[str, Any]],
    recommendation: str,
    is_new: bool,
    region: str,
    now: datetime,
) -> Dict[str, Any]:
    first_seen_z = iso_z(first_seen)
    last_seen_z = iso_z(last_seen)

    # Deterministic ID (v1): stable across reruns for the same logical incident
    primary = incident_primary_key(inc_type, evidence)
    incident_id = stable_hash16(f"v1|{inc_type}|{first_seen_z}|{last_seen_z}|{primary}|{region}")

    return {
        "incident_id": incident_id,
        "type": inc_type,
        "severity": severity,
        "title": title,
        "first_seen": first_seen_z,
        "last_seen": last_seen_z,
        "age": human_age(now, last_seen),
        "count": count,
        "evidence_count": count,
        "sample_count": len(samples),
        "is_new": is_new,
        "evidence": evidence,
        "samples": samples,
        "recommendation": recommendation,
    }


def severity_scale(count: int, medium: int, high: int) -> str:
    if count >= high:
        return "high"
    if count >= medium:
        return "medium"
    return "low"


# -------------------------
# Detectors (SOC-style)
# -------------------------

SENSITIVE_IAM = {
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
    "updateassumerolepolicy",
    "putrolepolicy",
}


def is_denied(e: Event) -> bool:
    c = (e.error_code or "").lower()
    return ("accessdenied" in c) or ("unauthorized" in c)


def is_invalid_ami(e: Event) -> bool:
    return (e.event_name or "").lower() == "runinstances" and (e.error_code or "").lower() == "invalidamiid.malformed"


def is_signin_failure(e: Event) -> bool:
    # CloudTrail sign-in failures commonly show these, but formats vary.
    src = (e.event_source or "").lower()
    name = (e.event_name or "").lower()
    code = (e.error_code or "").lower()
    return (
        "signin.amazonaws.com" in src
        or name in {"consolelogin", "credentialchallenge"}
        or "failedauthentication" in code
        or "invalid" in code and "token" in code
    )


def detect_spike_family(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    window_minutes: int,
    inc_type: str,
    title_prefix: str,
    match_fn,
    hard_min_threshold: int,
    sev_medium: int,
    sev_high: int,
    recommendation: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    """
    Generic spike detector:
    - Bins events per minute across the whole lookback range
    - Builds a baseline threshold from minute counts
    - Slides a window (10 minutes) and flags windows that exceed threshold
    - Produces "incident clusters" (merged adjacent windows)
    """
    # We only consider events with timestamps
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time  # type: ignore[assignment]
    end = ev[-1].event_time   # type: ignore[assignment]
    assert start and end

    # Bins for matched events
    matched = [e for e in ev if match_fn(e)]
    if not matched:
        return []

    # Build per-minute counts for matched events
    min_bins = build_minute_bins(matched, start, end)
    all_minutes = sorted(min_bins.keys())
    series = [len(min_bins[m]) for m in all_minutes]

    threshold = compute_baseline_threshold(series, hard_min_threshold, multiplier=3.0)

    if debug:
        print(f"[DEBUG] {inc_type}: matched_events={len(matched)} minute_bins={len(all_minutes)} auto_threshold={threshold}")

    # Sliding window over minutes: sum counts in last N minutes
    window = timedelta(minutes=window_minutes)

    # We'll compute "window_count" by summing minute bins in the window.
    # For speed with small data, brute force is fine.
    flagged_windows: List[Tuple[datetime, datetime, int, List[Event]]] = []
    for anchor in all_minutes:
        w_start = anchor
        w_end = anchor + window
        window_events: List[Event] = []
        cnt = 0
        for m in all_minutes:
            if m < w_start:
                continue
            if m > w_end:
                break
            bucket_events = min_bins.get(m, [])
            cnt += len(bucket_events)
            window_events.extend(bucket_events)

        if cnt >= threshold:
            flagged_windows.append((w_start, w_end, cnt, window_events))

    if not flagged_windows:
        return []

    # Merge adjacent/overlapping windows into incident clusters
    flagged_windows.sort(key=lambda x: x[0])
    clusters: List[Tuple[datetime, datetime, List[Event]]] = []
    cur_s, cur_e, _, cur_events = flagged_windows[0]
    cur_set = list(cur_events)

    for w_s, w_e, _, w_events in flagged_windows[1:]:
        if w_s <= cur_e:  # overlap / touch
            if w_e > cur_e:
                cur_e = w_e
            cur_set.extend(w_events)
        else:
            clusters.append((cur_s, cur_e, cur_set))
            cur_s, cur_e = w_s, w_e
            cur_set = list(w_events)

    clusters.append((cur_s, cur_e, cur_set))

    incidents: List[Dict[str, Any]] = []
    for s, e, cevents in clusters:
        # Dedup by event_id
        seen = set()
        dedup: List[Event] = []
        for x in sorted(cevents, key=lambda z: z.event_time or utc_now()):
            if x.event_id and x.event_id in seen:
                continue
            if x.event_id:
                seen.add(x.event_id)
            dedup.append(x)

        if not dedup:
            continue

        first_seen = dedup[0].event_time or s
        last_seen = dedup[-1].event_time or e

        count = len(dedup)
        sev = severity_scale(count, sev_medium, sev_high)

        # Mark "new" if last_seen after last watermark
        is_new = bool(last_seen_dt and last_seen_dt < last_seen) if last_seen_dt else True

        evidence = {
            "window_minutes": window_minutes,
            "auto_threshold": threshold,
            "by_actor": top_n(count_by([x.actor for x in dedup])),
            "by_region": top_n(count_by([x.aws_region for x in dedup])),
            "by_eventName": top_n(count_by([x.event_name for x in dedup])),
        }

        incidents.append(make_incident(
            inc_type=inc_type,
            severity=sev,
            title=f"{title_prefix}: {count} events",
            first_seen=first_seen,
            last_seen=last_seen,
            count=count,
            evidence=evidence,
            samples=compact_samples(dedup),
            recommendation=recommendation,
            is_new=is_new,
            region=region,
            now=now,
        ))

    return incidents


def detect_new_region_usage(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    """
    New region usage:
    - Baseline = regions seen in first 7 days of lookback
    - Alert on regions that appear later that were not in baseline
    """
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time  # type: ignore[assignment]
    end = ev[-1].event_time   # type: ignore[assignment]
    assert start and end

    baseline_end = start + timedelta(days=7)
    baseline_regions = sorted({e.aws_region for e in ev if e.event_time and e.event_time <= baseline_end})

    later = [e for e in ev if e.event_time and e.event_time > baseline_end]
    new_regions = sorted({e.aws_region for e in later if e.aws_region not in baseline_regions})

    if debug:
        print(f"[DEBUG] new_region: baseline_days=7 baseline_regions={baseline_regions} new_regions={new_regions}")

    if not new_regions:
        return []

    hits = [e for e in later if e.aws_region in new_regions]
    hits.sort(key=lambda x: x.event_time or utc_now())
    first_seen = hits[0].event_time or start
    last_seen = hits[-1].event_time or end

    is_new = bool(last_seen_dt and last_seen_dt < last_seen) if last_seen_dt else True

    sev = "high" if len(new_regions) >= 3 else "medium"

    return [make_incident(
        inc_type="new_region_activity",
        severity=sev,
        title=f"New region(s) used: {', '.join(new_regions)}",
        first_seen=first_seen,
        last_seen=last_seen,
        count=len(hits),
        evidence={
            "baseline_regions": baseline_regions,
            "new_regions": new_regions,
            "by_actor": top_n(count_by([e.actor for e in hits])),
            "by_eventName": top_n(count_by([e.event_name for e in hits])),
        },
        samples=compact_samples(hits),
        recommendation="If those regions aren’t expected, investigate credential use and consider region guardrails (SCP/IAM conditions).",
        is_new=is_new,
        region=region,
        now=now,
    )]


def detect_api_burst_actor(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    window_minutes: int,
    debug: bool,
) -> List[Dict[str, Any]]:
    """
    API burst by actor (success OR fail):
    - Compute sliding windows over the last 30 days
    - Auto threshold based on distribution of window call counts
    """
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    # Bin all events into minute buckets
    start = ev[0].event_time  # type: ignore[assignment]
    end = ev[-1].event_time   # type: ignore[assignment]
    assert start and end

    # Build per-minute lists
    minute_bins = build_minute_bins(ev, start, end)
    minutes = sorted(minute_bins.keys())
    if not minutes:
        return []

    window = timedelta(minutes=window_minutes)

    # For each minute anchor, compute max actor count within window
    # And collect those maxima to build a baseline
    maxima: List[int] = []
    max_detail: List[Tuple[datetime, datetime, str, int, List[Event]]] = []

    for anchor in minutes:
        w_start = anchor
        w_end = anchor + window

        bucket_events: List[Event] = []
        for m in minutes:
            if m < w_start:
                continue
            if m > w_end:
                break
            bucket_events.extend(minute_bins.get(m, []))

        if not bucket_events:
            continue

        # Count calls by actor in this window
        counts = count_by([e.actor for e in bucket_events])
        top_actor, top_count = next(iter(counts.items()))
        maxima.append(top_count)
        max_detail.append((w_start, w_end, top_actor, top_count, bucket_events))

    threshold = compute_baseline_threshold(maxima, hard_min=300, multiplier=3.0)

    if debug:
        print(f"[DEBUG] api_burst: windows={len(maxima)} auto_threshold={threshold} (hard_min=300)")

    # Flag windows where top actor exceeds threshold
    flagged = [(s, e, actor, cnt, evs) for (s, e, actor, cnt, evs) in max_detail if cnt >= threshold]
    if not flagged:
        return []

    # Merge flagged windows into clusters by time, but keep actor-specific evidence
    flagged.sort(key=lambda x: x[0])
    clusters: List[Tuple[datetime, datetime, List[Tuple[str, int]], List[Event]]] = []

    cur_s, cur_e, cur_actor, cur_cnt, cur_evs = flagged[0]
    cur_actor_peaks: List[Tuple[str, int]] = [(cur_actor, cur_cnt)]
    cur_events = list(cur_evs)

    for s, e, actor, cnt, evs in flagged[1:]:
        if s <= cur_e:
            if e > cur_e:
                cur_e = e
            cur_actor_peaks.append((actor, cnt))
            cur_events.extend(evs)
        else:
            clusters.append((cur_s, cur_e, cur_actor_peaks, cur_events))
            cur_s, cur_e = s, e
            cur_actor_peaks = [(actor, cnt)]
            cur_events = list(evs)

    clusters.append((cur_s, cur_e, cur_actor_peaks, cur_events))

    incidents: List[Dict[str, Any]] = []
    for s, e, peaks, cevs in clusters:
        # Use last event time as "last_seen"
        cevs = [x for x in cevs if x.event_time]
        cevs.sort(key=lambda x: x.event_time or utc_now())
        if not cevs:
            continue

        first_seen = cevs[0].event_time or s
        last_seen = cevs[-1].event_time or e

        is_new = bool(last_seen_dt and last_seen_dt < last_seen) if last_seen_dt else True

        # Choose highest peak in cluster
        peaks_sorted = sorted(peaks, key=lambda t: t[1], reverse=True)
        peak_actor, peak_count = peaks_sorted[0]

        sev = severity_scale(peak_count, medium=600, high=1200)

        incidents.append(make_incident(
            inc_type="api_burst",
            severity=sev,
            title=f"API burst: '{peak_actor}' peaked at {peak_count} calls/{window_minutes}m",
            first_seen=first_seen,
            last_seen=last_seen,
            count=len(cevs),
            evidence={
                "window_minutes": window_minutes,
                "auto_threshold": threshold,
                "peak_actor": peak_actor,
                "peak_count": peak_count,
                "top_actors_in_cluster": peaks_sorted[:5],
                "by_eventName": top_n(count_by([x.event_name for x in cevs])),
                "by_region": top_n(count_by([x.aws_region for x in cevs])),
            },
            samples=compact_samples([x for x in cevs if x.actor == peak_actor] or cevs),
            recommendation="Confirm whether this actor is expected automation. If not, investigate scripted abuse or compromised creds; add guardrails/throttling.",
            is_new=is_new,
            region=region,
            now=now,
        ))

    return incidents


def detect_sensitive_iam_spike(events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now,
        last_seen_dt=last_seen_dt,
        region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="suspicious_iam_activity",
        title_prefix="Sensitive IAM activity spike",
        match_fn=lambda e: (e.event_name or "").lower() in SENSITIVE_IAM,
        hard_min_threshold=3,   # because even 3 IAM actions in 10m can be meaningful in small envs
        sev_medium=8,
        sev_high=20,
        recommendation="Review IAM changes. If unexpected, check surrounding CloudTrail events and lock down privilege-escalation paths.",
        debug=debug,
    )


def detect_access_denied_spikes(events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now,
        last_seen_dt=last_seen_dt,
        region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="access_denied_spike",
        title_prefix="AccessDenied/Unauthorized spike",
        match_fn=is_denied,
        hard_min_threshold=5,
        sev_medium=10,
        sev_high=25,
        recommendation="Verify the failing principal is expected. If not, investigate credential misuse or broken automation; tighten IAM and add alerts.",
        debug=debug,
    )


def detect_invalid_ami_attempts(events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now,
        last_seen_dt=last_seen_dt,
        region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="invalid_ami_spike",
        title_prefix="EC2 invalid AMI attempts",
        match_fn=is_invalid_ami,
        hard_min_threshold=1,   # even 1 is notable in a small lab
        sev_medium=5,
        sev_high=15,
        recommendation="Could be broken automation or probing. Verify who attempted RunInstances and whether it was intended.",
        debug=debug,
    )


def detect_signin_failures(events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now,
        last_seen_dt=last_seen_dt,
        region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="signin_failure_spike",
        title_prefix="Sign-in/auth failures spike",
        match_fn=is_signin_failure,
        hard_min_threshold=3,
        sev_medium=6,
        sev_high=15,
        recommendation="Investigate sign-in failure sources and actors. If unexpected, reset credentials and verify MFA/Identity Center settings.",
        debug=debug,
    )


# -------------------------
# Main
# -------------------------

def main() -> int:
    debug = has_flag("--debug")

    region = resolve_region(get_arg_value("--region"))
    table_name = (get_arg_value("--table") or DEFAULT_TABLE).strip()

    lookback_days_s = get_arg_value("--lookback-days")
    lookback_days = int(lookback_days_s) if (lookback_days_s and lookback_days_s.isdigit()) else LOOKBACK_DAYS

    max_items_s = get_arg_value("--max-items")
    if max_items_s and max_items_s.strip().isdigit():
        v = int(max_items_s)
        max_items: Optional[int] = None if v <= 0 else v
    else:
        max_items = None  # default: no cap (scan all lookback items)

    if not region:
        print("[ERROR] No AWS region found. Fix with one of:")
        print("  ./scripts/detection/run_detection.py --region us-east-2")
        print("  export AWS_REGION=us-east-2")
        return 2

    ensure_parent_dir(OUT_PATH)
    ensure_parent_dir(STATE_PATH)

    state = read_state(STATE_PATH)
    last_seen = get_state_watermark(state)
    last_seen_dt = parse_iso8601(last_seen) if last_seen else None
    seen_incident_ids = set(get_state_seen_ids(state))

    if debug:
        print(f"[DEBUG] config region={region} table={table_name} lookback_days={lookback_days} max_items={'unlimited' if max_items is None else max_items}")
        print(f"[DEBUG] watermark last_seen_event_time={last_seen or 'none'}")

    # 1) Load
    raw_items = scan_last_days(table_name, region, lookback_days, max_items, debug)
    events = normalize_items(raw_items)

    now = utc_now()

    if not events:
        out = {
            "generated_at": iso_z(now),
            "region": region,
            "table": table_name,
            "lookback_days": lookback_days,
            "events_scanned": 0,
            "incident_count": 0,
            "incidents": [],
        }
        with open(OUT_PATH, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print("[OK] No events found → wrote out/incidents.json")
        return 0

    # 2) Run detectors (full 30-day view; SOC-style spike clustering)
    incidents: List[Dict[str, Any]] = []
    incidents.extend(detect_access_denied_spikes(events, now=now, last_seen_dt=last_seen_dt, region=region, debug=debug))
    incidents.extend(detect_sensitive_iam_spike(events, now=now, last_seen_dt=last_seen_dt, region=region, debug=debug))
    incidents.extend(detect_invalid_ami_attempts(events, now=now, last_seen_dt=last_seen_dt, region=region, debug=debug))
    incidents.extend(detect_signin_failures(events, now=now, last_seen_dt=last_seen_dt, region=region, debug=debug))
    incidents.extend(detect_new_region_usage(events, now=now, last_seen_dt=last_seen_dt, region=region, debug=debug))
    incidents.extend(detect_api_burst_actor(events, now=now, last_seen_dt=last_seen_dt, region=region, window_minutes=DETECT_WINDOW_MINUTES, debug=debug))

    # 2.5) Deduplicate incidents by deterministic incident_id
    dedup_map: Dict[str, Dict[str, Any]] = {}
    for inc in incidents:
        iid = str(inc.get("incident_id") or "")
        if not iid:
            continue
        prev = dedup_map.get(iid)
        if not prev:
            dedup_map[iid] = inc
            continue
        # keep the one with the newest last_seen (string sort works for ISO Z)
        if str(inc.get("last_seen") or "") > str(prev.get("last_seen") or ""):
            dedup_map[iid] = inc

    incidents = list(dedup_map.values())

    # Override is_new using persisted seen IDs (stable across reruns)
    for inc in incidents:
        iid = str(inc.get("incident_id") or "")
        if iid and iid in seen_incident_ids:
            inc["is_new"] = False

    # Sort incidents newest-first
    incidents.sort(key=lambda x: x.get("last_seen", ""), reverse=True)

    # 3) Compute newest event time for watermark (so next run flags "new" properly)
    newest_event_time = None
    for e in reversed(events):
        if e.event_time:
            newest_event_time = e.event_time
            break
    # Persist state:
    # - keep event watermark for troubleshooting
    # - keep seen incident IDs so reruns only show truly new incidents
    if newest_event_time:
        for inc in incidents:
            iid = str(inc.get("incident_id") or "")
            if iid:
                seen_incident_ids.add(iid)

        write_state(STATE_PATH, last_seen_event_time=iso_z(newest_event_time), seen_incident_ids=sorted(seen_incident_ids))

    # 4) Build output (timeline summary)
    time_range_oldest = events[0].event_time
    time_range_newest = events[-1].event_time

    # How many incidents are "new" since last run
    new_count = sum(1 for inc in incidents if inc.get("is_new"))

    output = {
        "generated_at": iso_z(now),
        "region": region,
        "table": table_name,
        "lookback_days": lookback_days,
        "window_minutes": DETECT_WINDOW_MINUTES,
        "events_scanned": len(events),
        "time_range": {
            "oldest": iso_z(time_range_oldest) if time_range_oldest else None,
            "newest": iso_z(time_range_newest) if time_range_newest else None,
        },
        "incident_count": len(incidents),
        "new_incident_count": new_count,
        "incidents": incidents,
    }

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # 5) Print a clean console summary (so you don't have to open JSON)
    print("\n=== AnomAI Detection Summary ===")
    print(f"events_scanned: {len(events)}")
    if time_range_oldest and time_range_newest:
        print(f"time_range: {iso_z(time_range_oldest)} .. {iso_z(time_range_newest)}")
    print(f"incidents: {len(incidents)} (new: {new_count})")

    if incidents:
        print("\nTop incidents (newest first):")
        for inc in incidents[:8]:
            flag = "🆕" if inc.get("is_new") else " "
            print(f"{flag} [{inc.get('severity','?').upper():6}] {inc.get('age','?'):>10}  {inc.get('title','')}")
    else:
        print("\nNo incidents detected in lookback window.")

    print(f"\n[OK] Wrote {OUT_PATH} and updated {STATE_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())