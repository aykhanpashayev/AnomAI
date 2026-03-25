#!/usr/bin/env python3
"""
AnomAI Unified Detection + API Conversion + DynamoDB Writer
===========================================================

Single-script pipeline:
- reads raw events from anomai_events
- runs the same detector logic as before
- converts incidents into the same API/UI schema as before
- writes final API-ready incidents directly into DynamoDB
- does not use any local watermark / seen-ID state

No local incidents.json or incidents_api.json files are used as system state.
"""

from __future__ import annotations

import json
import os
import sys
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Tuple   # FIX 1: added Set

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError


# ----------------------------
# Defaults
# ----------------------------

DEFAULT_REGION = "us-east-2"
DEFAULT_TABLE = "anomai_events"

LOOKBACK_DAYS = 120
DETECT_WINDOW_MINUTES = 10

DEST_TABLE = "anomai_incidents_api"


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


def ensure_parent_dir(path: str) -> None:   # FIX 2: only one definition kept
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
    try:
        s = boto3.session.Session()
        if s.region_name:
            return s.region_name
    except Exception:
        pass
    return DEFAULT_REGION


def scan_last_days(
    table_name: str,
    region: str,
    lookback_days: int,
    max_items: Optional[int],
    debug: bool,
) -> List[Dict[str, Any]]:
    session = boto3.session.Session(region_name=region)
    ddb = session.resource("dynamodb")
    table = ddb.Table(table_name)

    cutoff_day = (utc_now() - timedelta(days=lookback_days)).date().isoformat()
    filter_expr = Attr("day_bucket").gte(cutoff_day)

    items: List[Dict[str, Any]] = []
    last_key = None
    page = 0

    while True:
        page += 1
        kwargs: Dict[str, Any] = {"FilterExpression": filter_expr}
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


def build_minute_bins(
    events: List[Event],
    start: datetime,
    end: datetime,
) -> Dict[datetime, List[Event]]:
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
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def incident_primary_key(inc_type: str, evidence: Dict[str, Any]) -> str:
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
# Detectors
# -------------------------

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
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time  # type: ignore[assignment]
    end = ev[-1].event_time   # type: ignore[assignment]
    assert start and end

    matched = [e for e in ev if match_fn(e)]
    if not matched:
        return []

    min_bins = build_minute_bins(matched, start, end)
    all_minutes = sorted(min_bins.keys())
    series = [len(min_bins[m]) for m in all_minutes]
    threshold = compute_baseline_threshold(series, hard_min_threshold, multiplier=3.0)

    if debug:
        print(f"[DEBUG] {inc_type}: matched_events={len(matched)} minute_bins={len(all_minutes)} auto_threshold={threshold}")

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

    hits = sorted([e for e in later if e.aws_region in new_regions], key=lambda x: x.event_time or utc_now())
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
        recommendation="If those regions aren't expected, investigate credential use and consider region guardrails (SCP/IAM conditions).",
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
    ev = [e for e in events if e.event_time]
    if not ev:
        return []

    start = ev[0].event_time  # type: ignore[assignment]
    end = ev[-1].event_time   # type: ignore[assignment]
    assert start and end

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
        print(f"[DEBUG] api_burst: windows={len(maxima)} auto_threshold={threshold} (hard_min=300)")

    flagged = [(s, e, actor, cnt, evs) for (s, e, actor, cnt, evs) in max_detail if cnt >= threshold]
    if not flagged:
        return []

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
            recommendation="Confirm whether this actor is expected automation. If not, investigate scripted abuse or compromised creds; add guardrails/throttling.",
            is_new=is_new,
            region=region,
            now=now,
        ))

    return incidents


def detect_sensitive_iam_spike(
    events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events, now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="suspicious_iam_activity",
        title_prefix="Sensitive IAM activity spike",
        match_fn=lambda e: (e.event_name or "").lower() in SENSITIVE_IAM,
        hard_min_threshold=3, sev_medium=8, sev_high=20,
        recommendation="Review IAM changes. If unexpected, check surrounding CloudTrail events and lock down privilege-escalation paths.",
        debug=debug,
    )


def detect_access_denied_spikes(
    events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events, now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="access_denied_spike",
        title_prefix="AccessDenied/Unauthorized spike",
        match_fn=is_denied,
        hard_min_threshold=5, sev_medium=10, sev_high=25,
        recommendation="Verify the failing principal is expected. If not, investigate credential misuse or broken automation; tighten IAM and add alerts.",
        debug=debug,
    )


def detect_invalid_ami_attempts(
    events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events, now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="invalid_ami_spike",
        title_prefix="EC2 invalid AMI attempts",
        match_fn=is_invalid_ami,
        hard_min_threshold=1, sev_medium=5, sev_high=15,
        recommendation="Could be broken automation or probing. Verify who attempted RunInstances and whether it was intended.",
        debug=debug,
    )


def detect_signin_failures(
    events: List[Event], *, now: datetime, last_seen_dt: Optional[datetime], region: str, debug: bool
) -> List[Dict[str, Any]]:
    return detect_spike_family(
        events, now=now, last_seen_dt=last_seen_dt, region=region,
        window_minutes=DETECT_WINDOW_MINUTES,
        inc_type="signin_failure_spike",
        title_prefix="Sign-in/auth failures spike",
        match_fn=is_signin_failure,
        hard_min_threshold=3, sev_medium=6, sev_high=15,
        recommendation="Investigate sign-in failure sources and actors. If unexpected, reset credentials and verify MFA/Identity Center settings.",
        debug=debug,
    )


# ------------------------------------------------------------
# Converter helpers
# ------------------------------------------------------------

def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def to_int(x: Any, default: int = 0) -> int:
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


def severity_floor(sev: str) -> int:
    sev = (sev or "").lower()
    if sev == "high":
        return 80
    if sev == "medium":
        return 55
    return 25


def parse_iso8601_z(ts: Any) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def map_triggered_features(det_type: str) -> List[str]:
    return {
        "access_denied_spike":     ["ExcessiveAccessDenied"],
        "suspicious_iam_activity": ["SensitiveIAMActions"],
        "new_region_activity":     ["FirstTimeRegionUse"],
        "api_burst":               ["APIBurst"],
        "invalid_ami_spike":       ["InvalidAMI"],
        "signin_failure_spike":    ["SigninFailureSpike"],
    }.get(det_type, ["AnomalyDetected"])


def map_incident_type(det_type: str) -> str:
    return {
        "access_denied_spike":     "AccessDeniedSpike",
        "suspicious_iam_activity": "SensitiveIAMSpike",
        "api_burst":               "APIBurst",
        "new_region_activity":     "NewRegion",
        "signin_failure_spike":    "SigninFailureSpike",
        "invalid_ami_spike":       "InvalidAMISpike",
    }.get(det_type, "Anomaly")


def score_incident(det_type: str, severity: str, count: int, evidence: Any) -> int:
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
    Generate a stable inc_<YYYYMMDD>_<6-char-hash> ID.

    FIX 3: detected_at is NOT included in the fingerprint — it changes every
    run, which caused a new ID to be generated each time, making the
    skip-if-exists DynamoDB check useless.  Only immutable incident properties
    are used so the same incident always gets the same ID.
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
    det_type = str(det_inc.get("type") or "unknown")
    severity = str(det_inc.get("severity") or "low").lower()

    evidence = det_inc.get("evidence") or {}
    samples  = det_inc.get("samples") or []

    by_actor: Dict[str, int] = {}
    if isinstance(evidence, dict) and isinstance(evidence.get("by_actor"), dict):
        by_actor = evidence["by_actor"]

    actor = None
    if by_actor:
        actor = max(by_actor.items(), key=lambda kv: kv[1])[0]
    if not actor and samples:
        actor = samples[0].get("actor")
    if not actor:
        actor = "unknown"

    count          = to_int(det_inc.get("count"), 0)
    rule_score     = score_incident(det_type, severity, count, evidence)
    final_risk_score = rule_score
    ts_start       = det_inc.get("first_seen")
    ts_end         = det_inc.get("last_seen")
    is_new         = bool(det_inc.get("is_new", False))

    age_seconds: Optional[int] = None
    dt_detected = parse_iso8601_z(detected_at)
    dt_end      = parse_iso8601_z(ts_end) or parse_iso8601_z(ts_start)
    if dt_detected and dt_end:
        delta = dt_detected - dt_end
        age_seconds = max(0, int(delta.total_seconds()))

    return {
        "incident_id":        _generate_incident_id(det_inc, detected_at),
        "incident_type":      map_incident_type(det_type),
        "actor":              actor,
        "by_actor":           by_actor,
        "timestamp_start":    ts_start,
        "timestamp_end":      ts_end,
        "timestamp_detected": detected_at,
        "age_seconds":        age_seconds,
        "is_new":             is_new,
        "severity":           severity,
        "rule_score":         rule_score,
        "final_risk_score":   final_risk_score,
        "triggered_features": map_triggered_features(det_type),
        "explanation": {
            "summary":        det_inc.get("title") or det_type,
            "recommendation": det_inc.get("recommendation") or "",
        },
        "evidence": {
            "count":           count,
            "by_actor":        by_actor,
            "window_minutes":  evidence.get("window_minutes") if isinstance(evidence, dict) else None,
            "window_seconds":  (
                to_int(evidence.get("window_minutes"), 0) * 60
                if isinstance(evidence, dict) else None
            ),
            "top_event_names": (
                list((evidence.get("by_eventName") or {}).keys())[:5]
                if isinstance(evidence, dict) and isinstance(evidence.get("by_eventName"), dict)
                else []
            ),
        },
    }


# ------------------------------------------------------------
# DynamoDB writer helpers
# ------------------------------------------------------------

def convert_numbers_for_dynamodb(obj: Any) -> Any:
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: convert_numbers_for_dynamodb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [convert_numbers_for_dynamodb(v) for v in obj]
    return obj


def fetch_existing_incident_ids(region: str, table_name: str) -> Set[str]:
    """Return all incident_id values already in the destination table."""
    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)

    existing_ids: Set[str] = set()
    last_key = None

    while True:
        kwargs: Dict[str, Any] = {"ProjectionExpression": "incident_id"}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp = table.scan(**kwargs)
        for item in resp.get("Items", []):
            iid = item.get("incident_id")
            if iid:
                existing_ids.add(str(iid))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break

    return existing_ids


def write_new_incidents(
    region: str,
    table_name: str,
    incidents: List[Dict[str, Any]],
) -> None:
    """Write only new incidents using conditional put to prevent duplicates."""
    if not incidents:
        return

    ddb = boto3.resource("dynamodb", region_name=region)
    table = ddb.Table(table_name)

    written = 0
    skipped = 0

    for incident in incidents:
        iid = str(incident.get("incident_id") or "")
        if not iid:
            continue
        safe_item = convert_numbers_for_dynamodb(incident)
        safe_item["incident_id"] = iid
        try:
            table.put_item(
                Item=safe_item,
                ConditionExpression="attribute_not_exists(incident_id)",
            )
            written += 1
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConditionalCheckFailedException":
                skipped += 1
            else:
                raise

    if written or skipped:
        print(f"[DynamoDB] written={written} skipped_existing={skipped}")


# -------------------------
# Main
# -------------------------

def main() -> int:
    debug = has_flag("--debug")

    region       = resolve_region(get_arg_value("--region"))
    source_table = (get_arg_value("--table") or DEFAULT_TABLE).strip()
    dest_table   = (get_arg_value("--dest-table") or os.getenv("ANOMAI_DEST_TABLE") or DEST_TABLE).strip()

    lookback_days_s = get_arg_value("--lookback-days")
    lookback_days = int(lookback_days_s) if (lookback_days_s and lookback_days_s.isdigit()) else LOOKBACK_DAYS

    max_items_s = get_arg_value("--max-items")
    if max_items_s and max_items_s.strip().isdigit():
        v = int(max_items_s)
        max_items: Optional[int] = None if v <= 0 else v
    else:
        max_items = None

    if not region:
        print("[ERROR] No AWS region found.")
        print("  python pipeline.py --region us-east-2")
        print("  export AWS_REGION=us-east-2")
        return 2

    if debug:
        print(f"[DEBUG] region={region} source={source_table} dest={dest_table} lookback={lookback_days}d")

    raw_items = scan_last_days(source_table, region, lookback_days, max_items, debug)
    events    = normalize_items(raw_items)
    now       = utc_now()

    if not events:
        print(f"[OK] No events found in lookback window. No changes written to {dest_table}")
        return 0

    # Run all detectors
    incidents: List[Dict[str, Any]] = []
    incidents.extend(detect_access_denied_spikes(events, now=now, last_seen_dt=None, region=region, debug=debug))
    incidents.extend(detect_sensitive_iam_spike(events,  now=now, last_seen_dt=None, region=region, debug=debug))
    incidents.extend(detect_invalid_ami_attempts(events, now=now, last_seen_dt=None, region=region, debug=debug))
    incidents.extend(detect_signin_failures(events,      now=now, last_seen_dt=None, region=region, debug=debug))
    incidents.extend(detect_new_region_usage(events,     now=now, last_seen_dt=None, region=region, debug=debug))
    incidents.extend(detect_api_burst_actor(events,      now=now, last_seen_dt=None, region=region,
                                            window_minutes=DETECT_WINDOW_MINUTES, debug=debug))

    # Dedup by deterministic detector-side ID
    dedup_map: Dict[str, Dict[str, Any]] = {}
    for inc in incidents:
        iid = str(inc.get("incident_id") or "")
        if not iid:
            continue
        prev = dedup_map.get(iid)
        if not prev or str(inc.get("last_seen") or "") > str(prev.get("last_seen") or ""):
            dedup_map[iid] = inc
    incidents = list(dedup_map.values())

    # Convert to API schema
    detected_at = iso_z(now)
    converted   = [convert_one(inc, detected_at) for inc in incidents]

    # Mark is_new and filter to only genuinely new incidents
    existing_ids = fetch_existing_incident_ids(region, dest_table)
    new_converted: List[Dict[str, Any]] = []
    for inc in converted:
        iid = str(inc.get("incident_id") or "")
        if iid in existing_ids:
            inc["is_new"] = False
        else:
            inc["is_new"] = True
            new_converted.append(inc)

    write_new_incidents(region, dest_table, new_converted)

    time_range_oldest = events[0].event_time
    time_range_newest = events[-1].event_time
    new_count         = len(new_converted)

    # FIX 4 & 5: literal \n replaced with real newline via separate print()
    print()
    print("=== AnomAI Pipeline Summary ===")
    print(f"events_scanned:     {len(events)}")
    if time_range_oldest and time_range_newest:
        print(f"time_range:         {iso_z(time_range_oldest)} .. {iso_z(time_range_newest)}")
    print(f"detected_incidents: {len(converted)} (new: {new_count})")
    print(f"written_to_table:   {len(new_converted)} -> {dest_table}")

    if converted:
        print()
        print("Top API incidents (newest first):")
        for inc in converted[:8]:
            flag    = "NEW" if inc.get("is_new") else "   "
            sev     = inc.get("severity", "?").upper()
            iid     = inc.get("incident_id", "?")
            summary = (inc.get("explanation") or {}).get("summary", "")
            print(f"  [{flag}] [{sev:6}] {iid}  {summary}")
    else:
        print()
        print("No incidents detected in lookback window.")

    print()
    print(f"[OK] Updated {dest_table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())