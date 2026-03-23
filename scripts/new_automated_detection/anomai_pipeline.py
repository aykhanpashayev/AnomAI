#!/usr/bin/env python3
"""
AnomAI Unified Detection + Conversion Pipeline
===============================================

Combines the detection script and converter script into a single production
pipeline that operates fully in memory — no intermediate JSON files.

Flow:
  1. Scan DynamoDB table `anomai_events` (source)
  2. Normalize events
  3. Run all detectors (same logic as old detection script)
  4. Apply state / watermark / seen-incident dedup (same as before)
  5. Convert each incident to API-friendly structure (same as old converter)
  6. Write final items to DynamoDB table `anomai_incidents_api` (destination)

Usage:
  python anomai_pipeline.py
  python anomai_pipeline.py --region us-east-2 --debug
  python anomai_pipeline.py --dry-run
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_REGION = "us-east-2"
DEFAULT_SOURCE_TABLE = "anomai_events"
DEFAULT_DEST_TABLE = "anomai_incidents_api"
DEFAULT_LOOKBACK_DAYS = 90
DEFAULT_STATE_PATH = "out/detection_state.json"
DETECT_WINDOW_MINUTES = 10

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("anomai_pipeline")


# ===========================================================================
# Section 1: Shared Utilities
# ===========================================================================

def utc_now() -> datetime:
    """Return current time in UTC."""
    return datetime.now(timezone.utc)


def parse_iso8601(s: Any) -> Optional[datetime]:
    """Parse an ISO-8601 string (with or without trailing Z) into a UTC datetime."""
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
    """Render a datetime as an ISO-8601 UTC string ending in Z."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_parent_dir(path: str) -> None:
    """Create parent directories for a file path if they do not exist."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    """Safely deserialise a JSON string; return None on any failure."""
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def human_age(now: datetime, t: datetime) -> str:
    """Return a human-readable age string such as '2m ago', '5h ago', 'yesterday'."""
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
    """Floor a datetime to the minute boundary."""
    return dt.replace(second=0, microsecond=0)


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    """Clamp integer n to [lo, hi]."""
    return max(lo, min(hi, n))


def to_int(x: Any, default: int = 0) -> int:
    """Safely convert any value to int; return default on failure."""
    try:
        if x is None:
            return default
        if isinstance(x, bool):
            return default
        if isinstance(x, (int, float)):
            return int(x)
        s = str(x).strip()
        return int(float(s)) if s else default
    except Exception:
        return default


# ===========================================================================
# Section 2: Detection State (watermark + seen incident IDs)
# ===========================================================================

def read_state(path: str) -> Dict[str, Any]:
    """
    Load detection state from disk.
    Returns empty dict on any read / parse error (safe fallback).
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def write_state(
    path: str,
    *,
    last_seen_event_time: str,
    seen_incident_ids: List[str],
) -> None:
    """Persist detection state atomically."""
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


# ===========================================================================
# Section 3: Normalised Event Dataclass
# ===========================================================================

@dataclass
class Event:
    """A normalised CloudTrail event extracted from DynamoDB."""

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
    """
    Convert raw DynamoDB items into normalised Event objects.
    Malformed / missing fields are handled gracefully.
    """
    out: List[Event] = []

    for it in raw_items:
        try:
            event_id = str(it.get("event_id") or it.get("eventID") or it.get("id") or "")
            event_time_str = str(it.get("eventTime") or "")
            event_time = parse_iso8601(event_time_str)

            day_bucket_val = it.get("day_bucket") or ""
            day_bucket = str(day_bucket_val) if day_bucket_val else ""
            if not day_bucket and event_time:
                day_bucket = event_time.date().isoformat()

            aws_region = str(it.get("awsRegion") or "unknown")
            event_name = str(it.get("eventName") or "unknown")
            event_source = str(it.get("eventSource") or "unknown")
            actor = str(it.get("actor") or "unknown")
            source_ip = str(it.get("sourceIPAddress") or "unknown")

            ev_obj = safe_json_loads(it.get("event_json") or "")
            error_code = str(ev_obj.get("errorCode") or "") if ev_obj else ""
            error_message = str(ev_obj.get("errorMessage") or "") if ev_obj else ""

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
        except Exception as exc:
            log.warning("Skipping malformed DynamoDB item: %s", exc)

    out.sort(key=lambda e: e.event_time or datetime(1970, 1, 1, tzinfo=timezone.utc))
    return out


# ===========================================================================
# Section 4: DynamoDB Scanning
# ===========================================================================

def resolve_region(passed_region: Optional[str]) -> Optional[str]:
    """
    Resolve AWS region in priority order:
      1. CLI argument
      2. AWS_REGION / AWS_DEFAULT_REGION env vars
      3. boto3 session default
      4. Hard-coded project default
    """
    if passed_region and passed_region.strip():
        return passed_region.strip()

    env_region = (os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "").strip()
    if env_region:
        return env_region

    try:
        s = boto3.session.Session()
        if s.region_name:
            return s.region_name
    except Exception:
        pass

    return DEFAULT_REGION


def scan_source_table(
    table_name: str,
    region: str,
    lookback_days: int,
    debug: bool,
) -> List[Dict[str, Any]]:
    """
    Scan `anomai_events`, server-filtering by day_bucket >= cutoff.
    Handles pagination and AWS exceptions gracefully.
    """
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    cutoff_day = (utc_now() - timedelta(days=lookback_days)).date().isoformat()
    filter_expr = Attr("day_bucket").gte(cutoff_day)

    items: List[Dict[str, Any]] = []
    last_key = None
    page = 0

    try:
        while True:
            page += 1
            kwargs: Dict[str, Any] = {"FilterExpression": filter_expr}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = table.scan(**kwargs)
            got = resp.get("Items", [])
            items.extend(got)

            if debug:
                log.debug(
                    "Scan page=%d got=%d total=%d cutoff_day=%s",
                    page, len(got), len(items), cutoff_day,
                )

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    except (BotoCoreError, ClientError) as exc:
        log.error("DynamoDB scan failed: %s", exc)
        raise

    if debug and items:
        days = [it.get("day_bucket", "") for it in items if it.get("day_bucket")]
        if days:
            log.debug(
                "Scan complete: returned=%d day_bucket_range=%s..%s",
                len(items), min(days), max(days),
            )

    return items


# ===========================================================================
# Section 5: Counting + Auto-threshold Helpers
# ===========================================================================

def count_by(items: List[str]) -> Dict[str, int]:
    """Return a dict of {value: count} sorted descending by count."""
    m: Dict[str, int] = {}
    for x in items:
        m[x] = m.get(x, 0) + 1
    return dict(sorted(m.items(), key=lambda kv: kv[1], reverse=True))


def top_n(d: Dict[str, int], n: int = 8) -> Dict[str, int]:
    """Return the top-N entries from a count dict."""
    return dict(list(d.items())[:n])


def build_minute_bins(
    events: List[Event],
    start: datetime,
    end: datetime,
) -> Dict[datetime, List[Event]]:
    """Bin events into 1-minute buckets within [start, end]."""
    bins: Dict[datetime, List[Event]] = {}
    for e in events:
        if not e.event_time:
            continue
        if e.event_time < start or e.event_time > end:
            continue
        b = minute_bucket(e.event_time)
        bins.setdefault(b, []).append(e)
    return bins


def compute_baseline_threshold(
    series: List[int],
    hard_min: int,
    multiplier: float = 3.0,
) -> int:
    """
    Compute a simple auto-threshold without external math libraries:
      threshold = max(hard_min, median + multiplier * IQR)
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


# ===========================================================================
# Section 6: Incident Builders (detection side)
# ===========================================================================

def compact_samples(events: List[Event], max_samples: int = 6) -> List[Dict[str, Any]]:
    """Return up to max_samples condensed event dicts for evidence."""
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
            "errorMessage": (
                (e.error_message[:220] + "…") if len(e.error_message) > 220 else e.error_message
            ),
        })
    return out


def stable_hash16(s: str) -> str:
    """Return the first 16 hex chars of SHA-256(s)."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def incident_primary_key(inc_type: str, evidence: Dict[str, Any]) -> str:
    """
    Derive a stable discriminator for incident_id generation,
    preferring the top actor from evidence.
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
    """Construct a raw detection-side incident dict with a deterministic ID."""
    first_seen_z = iso_z(first_seen)
    last_seen_z = iso_z(last_seen)

    primary = incident_primary_key(inc_type, evidence)
    incident_id = stable_hash16(
        f"v1|{inc_type}|{first_seen_z}|{last_seen_z}|{primary}|{region}"
    )

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
    """Map an event count to a severity label."""
    if count >= high:
        return "high"
    if count >= medium:
        return "medium"
    return "low"


# ===========================================================================
# Section 7: Detectors
# ===========================================================================

# IAM actions considered sensitive for privilege-escalation detection
SENSITIVE_IAM = {
    "createuser", "createaccesskey", "putuserpolicy", "attachuserpolicy",
    "attachgrouppolicy", "attachrolepolicy", "addusertogroup",
    "updateloginprofile", "createpolicy", "createpolicyversion",
    "setdefaultpolicyversion", "passrole", "updateassumerolepolicy",
    "putrolepolicy",
}


def is_denied(e: Event) -> bool:
    c = (e.error_code or "").lower()
    return ("accessdenied" in c) or ("unauthorized" in c)


def is_invalid_ami(e: Event) -> bool:
    return (
        (e.event_name or "").lower() == "runinstances"
        and (e.error_code or "").lower() == "invalidamiid.malformed"
    )


def is_signin_failure(e: Event) -> bool:
    src = (e.event_source or "").lower()
    name = (e.event_name or "").lower()
    code = (e.error_code or "").lower()
    return (
        "signin.amazonaws.com" in src
        or name in {"consolelogin", "credentialchallenge"}
        or "failedauthentication" in code
        or ("invalid" in code and "token" in code)
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
    Generic spike detector shared by all spike-family detectors.
    Bins matched events per minute, computes an auto-threshold from the
    distribution, slides a window, merges adjacent flagged windows into
    clusters, and returns one incident per cluster.
    """
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time   # type: ignore[assignment]
    end = ev[-1].event_time    # type: ignore[assignment]

    matched = [e for e in ev if match_fn(e)]
    if not matched:
        return []

    min_bins = build_minute_bins(matched, start, end)
    all_minutes = sorted(min_bins.keys())
    series = [len(min_bins[m]) for m in all_minutes]
    threshold = compute_baseline_threshold(series, hard_min_threshold, multiplier=3.0)

    if debug:
        log.debug(
            "%s: matched_events=%d minute_bins=%d auto_threshold=%d",
            inc_type, len(matched), len(all_minutes), threshold,
        )

    window = timedelta(minutes=window_minutes)
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

    # Merge adjacent / overlapping flagged windows into clusters
    flagged_windows.sort(key=lambda x: x[0])
    clusters: List[Tuple[datetime, datetime, List[Event]]] = []
    cur_s, cur_e, _, cur_events = flagged_windows[0]
    cur_set = list(cur_events)

    for w_s, w_e, _, w_events in flagged_windows[1:]:
        if w_s <= cur_e:
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
        # Dedup events within the cluster by event_id
        seen: set = set()
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
    Detect usage of AWS regions not seen in the first 7 days of the lookback
    window.  Alerts on regions that appear only after the baseline period.
    """
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time   # type: ignore[assignment]
    end = ev[-1].event_time    # type: ignore[assignment]

    baseline_end = start + timedelta(days=7)
    baseline_regions = sorted({
        e.aws_region for e in ev if e.event_time and e.event_time <= baseline_end
    })

    later = [e for e in ev if e.event_time and e.event_time > baseline_end]
    new_regions = sorted({e.aws_region for e in later if e.aws_region not in baseline_regions})

    if debug:
        log.debug(
            "new_region: baseline_regions=%s new_regions=%s",
            baseline_regions, new_regions,
        )

    if not new_regions:
        return []

    hits = sorted(
        [e for e in later if e.aws_region in new_regions],
        key=lambda x: x.event_time or utc_now(),
    )
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
        recommendation=(
            "If those regions aren't expected, investigate credential use "
            "and consider region guardrails (SCP/IAM conditions)."
        ),
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
    Detect per-actor API call bursts using sliding windows over the full
    lookback range.  Auto-threshold derived from distribution of window maxima.
    """
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time   # type: ignore[assignment]
    end = ev[-1].event_time    # type: ignore[assignment]

    minute_bins = build_minute_bins(ev, start, end)
    minutes = sorted(minute_bins.keys())
    if not minutes:
        return []

    window = timedelta(minutes=window_minutes)
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
        counts = count_by([e.actor for e in bucket_events])
        top_actor, top_count = next(iter(counts.items()))
        maxima.append(top_count)
        max_detail.append((w_start, w_end, top_actor, top_count, bucket_events))

    threshold = compute_baseline_threshold(maxima, hard_min=300, multiplier=3.0)

    if debug:
        log.debug(
            "api_burst: windows=%d auto_threshold=%d (hard_min=300)", len(maxima), threshold
        )

    flagged = [
        (s, e, actor, cnt, evs)
        for (s, e, actor, cnt, evs) in max_detail if cnt >= threshold
    ]
    if not flagged:
        return []

    # Merge flagged windows into time-contiguous clusters
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
        cevs = sorted([x for x in cevs if x.event_time], key=lambda x: x.event_time or utc_now())
        if not cevs:
            continue

        first_seen = cevs[0].event_time or s
        last_seen = cevs[-1].event_time or e
        is_new = bool(last_seen_dt and last_seen_dt < last_seen) if last_seen_dt else True

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
            recommendation=(
                "Confirm whether this actor is expected automation. If not, investigate "
                "scripted abuse or compromised creds; add guardrails/throttling."
            ),
            is_new=is_new,
            region=region,
            now=now,
        ))

    return incidents


# Thin wrappers that delegate to detect_spike_family with the right parameters

def detect_sensitive_iam_spike(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="suspicious_iam_activity",
        title_prefix="Sensitive IAM activity spike",
        match_fn=lambda e: (e.event_name or "").lower() in SENSITIVE_IAM,
        hard_min_threshold=3,
        sev_medium=8, sev_high=20,
        recommendation=(
            "Review IAM changes. If unexpected, check surrounding CloudTrail events "
            "and lock down privilege-escalation paths."
        ),
        debug=debug,
    )


def detect_access_denied_spikes(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="access_denied_spike",
        title_prefix="AccessDenied/Unauthorized spike",
        match_fn=is_denied,
        hard_min_threshold=5,
        sev_medium=10, sev_high=25,
        recommendation=(
            "Verify the failing principal is expected. If not, investigate credential "
            "misuse or broken automation; tighten IAM and add alerts."
        ),
        debug=debug,
    )


def detect_invalid_ami_attempts(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="invalid_ami_spike",
        title_prefix="EC2 invalid AMI attempts",
        match_fn=is_invalid_ami,
        hard_min_threshold=1,
        sev_medium=5, sev_high=15,
        recommendation=(
            "Could be broken automation or probing. Verify who attempted RunInstances "
            "and whether it was intended."
        ),
        debug=debug,
    )


def detect_signin_failures(
    events: List[Event],
    *,
    now: datetime,
    last_seen_dt: Optional[datetime],
    region: str,
    debug: bool,
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events,
        now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="signin_failure_spike",
        title_prefix="Sign-in/auth failures spike",
        match_fn=is_signin_failure,
        hard_min_threshold=3,
        sev_medium=6, sev_high=15,
        recommendation=(
            "Investigate sign-in failure sources and actors. If unexpected, reset "
            "credentials and verify MFA/Identity Center settings."
        ),
        debug=debug,
    )


# ===========================================================================
# Section 8: Conversion Helpers (converter side)
# ===========================================================================

def severity_floor(sev: str) -> int:
    """Return the minimum rule_score for a given severity label."""
    sev = (sev or "").lower()
    if sev == "high":
        return 80
    if sev == "medium":
        return 55
    return 25


def map_triggered_features(det_type: str) -> List[str]:
    """Map detection type string to triggered-feature labels."""
    m = {
        "access_denied_spike": ["ExcessiveAccessDenied"],
        "suspicious_iam_activity": ["SensitiveIAMActions"],
        "new_region_activity": ["FirstTimeRegionUse"],
        "api_burst": ["APIBurst"],
        "invalid_ami_spike": ["InvalidAMI"],
        "signin_failure_spike": ["SigninFailureSpike"],
    }
    return m.get(det_type, ["AnomalyDetected"])


def map_incident_type(det_type: str) -> str:
    """Map internal detection type to the public API incident_type string."""
    m = {
        "access_denied_spike": "AccessDeniedSpike",
        "suspicious_iam_activity": "SensitiveIAMSpike",
        "api_burst": "APIBurst",
        "new_region_activity": "NewRegion",
        "signin_failure_spike": "SigninFailureSpike",
        "invalid_ami_spike": "InvalidAMISpike",
    }
    return m.get(det_type, "Anomaly")


def score_incident(
    det_type: str,
    severity: str,
    count: int,
    evidence: Any,
) -> int:
    """
    Evidence-aware rule scoring.  Returns an integer in [0, 100].
    Mirrors the original converter's scoring logic exactly.
    """
    det_type = (det_type or "").strip()
    count_i = max(0, to_int(count, 0))
    ev: Dict[str, Any] = evidence if isinstance(evidence, dict) else {}

    auto_thr = to_int(ev.get("auto_threshold"), 0)
    if auto_thr <= 0:
        if det_type == "access_denied_spike":
            auto_thr = 5
        elif det_type == "suspicious_iam_activity":
            auto_thr = 3
        elif det_type == "api_burst":
            auto_thr = 300
        else:
            auto_thr = 5

    base = 0

    if det_type == "access_denied_spike":
        ratio = count_i / max(auto_thr, 1)
        base = int(round(20 + 15 * ratio))

    elif det_type == "api_burst":
        peak = to_int(ev.get("peak_count"), count_i)
        ratio = peak / max(auto_thr, 1)
        base = int(round(30 + 20 * ratio))

    elif det_type == "suspicious_iam_activity":
        by_event = ev.get("by_eventName") if isinstance(ev.get("by_eventName"), dict) else {}
        diversity = len(by_event) if isinstance(by_event, dict) else 1
        base = int(round(25 + 8 * count_i + 4 * diversity))

    elif det_type == "new_region_activity":
        new_regions = ev.get("new_regions") if isinstance(ev.get("new_regions"), list) else []
        n_new = len(new_regions) if isinstance(new_regions, list) else 1
        base = 50 + 15 * max(0, n_new - 1)

    elif det_type in ("signin_failure_spike", "invalid_ami_spike"):
        base = 20 + 12 * count_i

    else:
        ratio = count_i / max(auto_thr, 1)
        base = int(round(20 + 10 * ratio))

    base = clamp(base, 0, 100)
    base = max(base, severity_floor(severity))
    return clamp(base, 0, 100)


def _generate_incident_id(det_inc: Dict[str, Any], detected_at: Optional[str]) -> str:
    """
    Generate the public API incident ID in the form  inc_<YYYYMMDD>_<6-char hash>.

    The fingerprint is built ONLY from the incident's immutable properties
    (type, first_seen, last_seen, severity) — NOT from detected_at, which
    changes every run and would produce a different ID each time.
    This guarantees the same incident always gets the same ID across reruns,
    which is required for skip-if-exists dedup in DynamoDB.
    """
    fingerprint = "|".join([
        str(det_inc.get("type") or ""),
        str(det_inc.get("first_seen") or ""),
        str(det_inc.get("last_seen") or ""),
        str(det_inc.get("severity") or ""),
    ])
    h = hashlib.sha1(fingerprint.encode()).hexdigest()[:6]

    ts = det_inc.get("first_seen") or detected_at or ""
    date_prefix = ts[:10].replace("-", "") if len(ts) >= 10 else ""
    return f"inc_{date_prefix}_{h}"


def convert_one(det_inc: Dict[str, Any], detected_at: Optional[str]) -> Dict[str, Any]:
    """
    Convert a single raw detection-side incident into the API / UI schema.
    Preserves all field mappings from the original converter script.
    """
    det_type = str(det_inc.get("type") or "unknown")
    severity = str(det_inc.get("severity") or "low").lower()

    evidence = det_inc.get("evidence") or {}
    samples = det_inc.get("samples") or []

    # Preserve full by_actor dict for multi-actor UI support
    by_actor: Dict[str, int] = {}
    if isinstance(evidence, dict) and isinstance(evidence.get("by_actor"), dict):
        by_actor = evidence["by_actor"]

    # Resolve primary actor (top by call count → first sample → unknown)
    actor: Optional[str] = None
    if by_actor:
        actor = max(by_actor.items(), key=lambda kv: kv[1])[0]
    if not actor and samples:
        actor = samples[0].get("actor")
    if not actor:
        actor = "unknown"

    count = to_int(det_inc.get("count"), 0)
    rule_score = score_incident(det_type, severity, count, evidence)
    final_risk_score = rule_score

    ts_start = det_inc.get("first_seen")
    ts_end = det_inc.get("last_seen")
    is_new = bool(det_inc.get("is_new", False))

    # age_seconds = detected_at − timestamp_end (fall back to timestamp_start)
    age_seconds: Optional[int] = None
    dt_detected = parse_iso8601(detected_at)
    dt_end = parse_iso8601(ts_end) or parse_iso8601(ts_start)
    if dt_detected and dt_end:
        delta = dt_detected - dt_end
        age_seconds = max(0, int(delta.total_seconds()))

    return {
        "incident_id": _generate_incident_id(det_inc, detected_at),
        "incident_type": map_incident_type(det_type),
        "actor": actor,
        "by_actor": by_actor,
        "timestamp_start": ts_start,
        "timestamp_end": ts_end,
        "timestamp_detected": detected_at,
        "age_seconds": age_seconds,
        "is_new": is_new,
        "severity": severity,
        "rule_score": rule_score,
        "final_risk_score": final_risk_score,
        "triggered_features": map_triggered_features(det_type),
        "explanation": {
            "summary": det_inc.get("title") or det_type,
            "recommendation": det_inc.get("recommendation") or "",
        },
        "evidence": {
            "count": count,
            "by_actor": by_actor,
            "window_minutes": (
                evidence.get("window_minutes") if isinstance(evidence, dict) else None
            ),
            "window_seconds": (
                to_int(evidence.get("window_minutes"), 0) * 60
                if isinstance(evidence, dict) else None
            ),
            "top_event_names": (
                list((evidence.get("by_eventName") or {}).keys())[:5]
                if isinstance(evidence, dict)
                and isinstance(evidence.get("by_eventName"), dict)
                else []
            ),
        },
    }


# ===========================================================================
# Section 9: DynamoDB Write Helpers
# ===========================================================================

def _to_decimal(value: Any) -> Any:
    """
    Recursively convert float values to Decimal for DynamoDB compatibility.
    DynamoDB does not accept Python float; Decimal is required.
    """
    if isinstance(value, float):
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return Decimal("0")
    if isinstance(value, dict):
        return {k: _to_decimal(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_decimal(item) for item in value]
    return value


def write_incidents_to_dynamo(
    items: List[Dict[str, Any]],
    table_name: str,
    region: str,
    dry_run: bool,
    debug: bool,
) -> Tuple[int, int]:
    """
    Write new incident items to the destination DynamoDB table.

    Uses DynamoDB ConditionExpression attribute_not_exists(incident_id) on each
    put_item call so the database itself enforces skip-if-exists atomically.
    No pre-fetch scan needed — each write is rejected at the DB level if the
    item already exists.

    Returns (written, skipped) counts.
    Floats are converted to Decimal automatically.
    """
    if dry_run:
        log.info("[DRY RUN] Would write %d items to %s (skip-if-exists)", len(items), table_name)
        return len(items), 0

    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    written = 0
    skipped = 0

    for item in items:
        iid = str(item.get("incident_id") or "")
        if not iid:
            log.warning("Skipping item with missing incident_id: %s", item)
            skipped += 1
            continue

        safe_item = _to_decimal(item)
        safe_item["incident_id"] = iid  # ensure string PK

        try:
            table.put_item(
                Item=safe_item,
                ConditionExpression="attribute_not_exists(incident_id)",
            )
            written += 1
            if debug:
                log.debug("Wrote incident_id=%s", iid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                # Item already exists — skip silently
                skipped += 1
                if debug:
                    log.debug("Skipped (already exists) incident_id=%s", iid)
            else:
                log.error("DynamoDB put_item failed for incident_id=%s: %s", iid, exc)
                raise

    return written, skipped


# ===========================================================================
# Section 10: CLI Argument Parsing
# ===========================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AnomAI Unified Detection + Conversion Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--region",
        default=None,
        help="AWS region (falls back to env vars then us-east-2)",
    )
    p.add_argument(
        "--source-table",
        default=DEFAULT_SOURCE_TABLE,
        help="Source DynamoDB table (CloudTrail events)",
    )
    p.add_argument(
        "--dest-table",
        default=DEFAULT_DEST_TABLE,
        help="Destination DynamoDB table (API-friendly incidents)",
    )
    p.add_argument(
        "--lookback-days",
        type=int,
        default=DEFAULT_LOOKBACK_DAYS,
        help="Number of days to look back when scanning events",
    )
    p.add_argument(
        "--state-path",
        default=DEFAULT_STATE_PATH,
        help="Path to detection state file (watermark + seen incident IDs)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Run the full pipeline but skip writing to DynamoDB",
    )
    p.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging",
    )
    return p


# ===========================================================================
# Section 11: Main Entrypoint
# ===========================================================================

def main() -> int:
    """
    Unified pipeline entrypoint:
      1. Parse CLI args
      2. Load state (watermark + seen incident IDs)
      3. Scan anomai_events
      4. Normalize events
      5. Run all detectors
      6. Dedup + apply seen-incident state
      7. Convert to API schema (same as old converter)
      8. Write to anomai_incidents_api (or dry-run)
      9. Persist updated state
      10. Print summary
    """
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        log.debug("Debug logging enabled")

    region = resolve_region(args.region)
    if not region:
        log.error(
            "No AWS region found.  Use --region us-east-2 or export AWS_REGION=us-east-2"
        )
        return 2

    log.info(
        "Config: region=%s source=%s dest=%s lookback=%dd dry_run=%s",
        region,
        args.source_table,
        args.dest_table,
        args.lookback_days,
        args.dry_run,
    )

    # ------------------------------------------------------------------
    # Step 1: Load detection state
    # ------------------------------------------------------------------
    ensure_parent_dir(args.state_path)
    state = read_state(args.state_path)
    last_seen = get_state_watermark(state)
    last_seen_dt = parse_iso8601(last_seen) if last_seen else None
    seen_incident_ids: set = set(get_state_seen_ids(state))

    if args.debug:
        log.debug("Watermark last_seen_event_time=%s", last_seen or "none")
        log.debug("Seen incident IDs loaded: %d", len(seen_incident_ids))

    # ------------------------------------------------------------------
    # Step 2: Scan source table
    # ------------------------------------------------------------------
    try:
        raw_items = scan_source_table(
            args.source_table, region, args.lookback_days, args.debug
        )
    except (BotoCoreError, ClientError) as exc:
        log.error("Failed to scan source table '%s': %s", args.source_table, exc)
        return 1

    events = normalize_items(raw_items)
    now = utc_now()

    if not events:
        log.info("No events found in lookback window — nothing to detect.")
        print("\n=== AnomAI Pipeline Summary ===")
        print("events_scanned : 0")
        print("incidents      : 0 (new: 0)")
        print("[OK] No events found — destination table unchanged.")
        return 0

    log.info("Events loaded: %d", len(events))

    # ------------------------------------------------------------------
    # Step 3: Run detectors (same order as old detection script)
    # ------------------------------------------------------------------
    raw_incidents: List[Dict[str, Any]] = []
    raw_incidents.extend(
        detect_access_denied_spikes(
            events, now=now, last_seen_dt=last_seen_dt, region=region, debug=args.debug
        )
    )
    raw_incidents.extend(
        detect_sensitive_iam_spike(
            events, now=now, last_seen_dt=last_seen_dt, region=region, debug=args.debug
        )
    )
    raw_incidents.extend(
        detect_invalid_ami_attempts(
            events, now=now, last_seen_dt=last_seen_dt, region=region, debug=args.debug
        )
    )
    raw_incidents.extend(
        detect_signin_failures(
            events, now=now, last_seen_dt=last_seen_dt, region=region, debug=args.debug
        )
    )
    raw_incidents.extend(
        detect_new_region_usage(
            events, now=now, last_seen_dt=last_seen_dt, region=region, debug=args.debug
        )
    )
    raw_incidents.extend(
        detect_api_burst_actor(
            events,
            now=now,
            last_seen_dt=last_seen_dt,
            region=region,
            window_minutes=DETECT_WINDOW_MINUTES,
            debug=args.debug,
        )
    )

    # ------------------------------------------------------------------
    # Step 4: Dedup raw incidents by detector-side stable_hash16 ID
    # (dedup happens before conversion; we use the internal detector key here)
    # ------------------------------------------------------------------
    dedup_map: Dict[str, Dict[str, Any]] = {}
    for inc in raw_incidents:
        iid = str(inc.get("incident_id") or "")
        if not iid:
            continue
        prev = dedup_map.get(iid)
        if not prev:
            dedup_map[iid] = inc
            continue
        # Keep the variant with the newer last_seen (ISO-Z strings sort correctly)
        if str(inc.get("last_seen") or "") > str(prev.get("last_seen") or ""):
            dedup_map[iid] = inc

    raw_incidents = list(dedup_map.values())

    # Sort newest-first (matches old detection script output order)
    raw_incidents.sort(key=lambda x: x.get("last_seen", ""), reverse=True)

    # ------------------------------------------------------------------
    # Step 5: Convert to API schema (same logic as old converter).
    # The API incident_id is always the inc_<date>_<hash> format from
    # _generate_incident_id.  We apply the seen-incident check AFTER
    # conversion so we compare against the same inc_ IDs stored in state.
    # ------------------------------------------------------------------
    detected_at = iso_z(now)  # matches generated_at from old detection output
    api_incidents: List[Dict[str, Any]] = [
        convert_one(inc, detected_at) for inc in raw_incidents
    ]

    # Apply persisted seen-incident IDs (API-side inc_ IDs) so is_new is
    # stable across reruns without changing the conversion logic.
    for api_inc in api_incidents:
        api_iid = str(api_inc.get("incident_id") or "")
        if api_iid and api_iid in seen_incident_ids:
            api_inc["is_new"] = False

    # ------------------------------------------------------------------
    # Step 6: Write to destination DynamoDB table (skip existing incidents)
    # ------------------------------------------------------------------
    try:
        written, skipped = write_incidents_to_dynamo(
            api_incidents,
            args.dest_table,
            region,
            dry_run=args.dry_run,
            debug=args.debug,
        )
    except (BotoCoreError, ClientError) as exc:
        log.error("Failed to write to dest table '%s': %s", args.dest_table, exc)
        return 1

    # ------------------------------------------------------------------
    # Step 7: Persist updated detection state (watermark + seen API inc_ IDs)
    # ------------------------------------------------------------------
    newest_event_time: Optional[datetime] = None
    for e in reversed(events):
        if e.event_time:
            newest_event_time = e.event_time
            break

    if newest_event_time:
        for api_inc in api_incidents:
            api_iid = str(api_inc.get("incident_id") or "")
            if api_iid:
                seen_incident_ids.add(api_iid)
        write_state(
            args.state_path,
            last_seen_event_time=iso_z(newest_event_time),
            seen_incident_ids=sorted(seen_incident_ids),
        )
        if args.debug:
            log.debug("State written to %s", args.state_path)

    # ------------------------------------------------------------------
    # Step 8: Console summary
    # ------------------------------------------------------------------
    time_oldest = events[0].event_time
    time_newest = events[-1].event_time
    new_count = sum(1 for inc in api_incidents if inc.get("is_new"))

    print("\n=== AnomAI Pipeline Summary ===")
    print(f"events_scanned  : {len(events)}")
    if time_oldest and time_newest:
        print(f"time_range      : {iso_z(time_oldest)} .. {iso_z(time_newest)}")
    print(f"incidents       : {len(api_incidents)} (new: {new_count})")
    print(f"written_to_db   : {written}  skipped_existing: {skipped}  (dest: {args.dest_table})")

    if api_incidents:
        print("\nAll incidents (newest first):")
        for api_inc in api_incidents:
            flag = "🆕" if api_inc.get("is_new") else "  "
            sev = (api_inc.get("severity") or "?").upper()
            inc_id = api_inc.get("incident_id", "?")
            inc_type = api_inc.get("incident_type", "?")
            score = api_inc.get("final_risk_score", "?")
            summary = (api_inc.get("explanation") or {}).get("summary", "")
            age_s = api_inc.get("age_seconds")
            age_str = f"{age_s}s ago" if age_s is not None else "?"
            print(f"  {flag} [{sev:6}] score={score:>3}  {age_str:>14}  [{inc_id}]  {summary}")
    else:
        print("\nNo incidents detected in lookback window.")

    if args.dry_run:
        print("\n[DRY RUN] No data was written to DynamoDB.")
    else:
        print(f"\n[OK] Wrote {written} new incidents, skipped {skipped} existing → {args.dest_table}")
        print(f"[OK] Updated state → {args.state_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())