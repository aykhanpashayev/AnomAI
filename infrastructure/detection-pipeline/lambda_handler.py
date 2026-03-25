#!/usr/bin/env python3
"""
AnomAI Lambda Handler
=====================
Wraps the detection pipeline for AWS Lambda execution.
Triggered every 5 minutes by EventBridge Scheduler.

Environment variables (set in Terraform, no hardcoded secrets):
  AWS_REGION            — set automatically by Lambda runtime
  ANOMAI_SOURCE_TABLE   — source DynamoDB table (anomai_events)
  ANOMAI_DEST_TABLE     — destination DynamoDB table (anomai_incidents_api)
  ANOMAI_LOOKBACK_DAYS  — how many days to scan (default: 120)
  ANOMAI_DEBUG          — set to "true" to enable debug logging (optional)
"""

from __future__ import annotations

import json
import logging
import os
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

# ----------------------------
# Logging
# ----------------------------
log = logging.getLogger()
log.setLevel(logging.INFO)

# ----------------------------
# Config from environment — no hardcoded secrets
# ----------------------------
SOURCE_TABLE  = os.environ.get("ANOMAI_SOURCE_TABLE",  "anomai_events")
DEST_TABLE    = os.environ.get("ANOMAI_DEST_TABLE",    "anomai_incidents_api")
LOOKBACK_DAYS = int(os.environ.get("ANOMAI_LOOKBACK_DAYS", "120"))
REGION        = os.environ.get("AWS_REGION", "us-east-2")

DETECT_WINDOW_MINUTES = 10

# Reuse boto3 resource across warm Lambda invocations (saves ~100ms per call)
_ddb = boto3.resource("dynamodb", region_name=REGION)


# ============================================================
# Shared utilities
# ============================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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


def parse_iso8601_z(ts: Any) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    s = ts.strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def safe_json_loads(s: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(s, str) or not s.strip():
        return None
    try:
        return json.loads(s)
    except Exception:
        return None


def human_age(now: datetime, t: datetime) -> str:
    sec = int((now - t).total_seconds())
    if sec < 0:
        sec = abs(sec)
        if sec < 60:    return f"in {sec}s"
        if sec < 3600:  return f"in {sec // 60}m"
        if sec < 86400: return f"in {sec // 3600}h"
        return f"in {sec // 86400}d"
    if sec < 60:    return f"{sec}s ago"
    if sec < 3600:  return f"{sec // 60}m ago"
    if sec < 86400: return f"{sec // 3600}h ago"
    days = sec // 86400
    return "yesterday" if days == 1 else f"{days}d ago"


def minute_bucket(dt: datetime) -> datetime:
    return dt.replace(second=0, microsecond=0)


def stable_hash16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def to_int(x: Any, default: int = 0) -> int:
    try:
        if x is None or isinstance(x, bool): return default
        if isinstance(x, (int, float)):       return int(x)
        s = str(x).strip()
        return int(float(s)) if s else default
    except Exception:
        return default


def count_by(items: List[str]) -> Dict[str, int]:
    m: Dict[str, int] = {}
    for x in items:
        m[x] = m.get(x, 0) + 1
    return dict(sorted(m.items(), key=lambda kv: kv[1], reverse=True))


def top_n(d: Dict[str, int], n: int = 8) -> Dict[str, int]:
    return dict(list(d.items())[:n])


def severity_scale(count: int, medium: int, high: int) -> str:
    if count >= high:   return "high"
    if count >= medium: return "medium"
    return "low"


def severity_floor(sev: str) -> int:
    s = (sev or "").lower()
    if s == "high":   return 80
    if s == "medium": return 55
    return 25


def convert_numbers_for_dynamodb(obj: Any) -> Any:
    if isinstance(obj, float): return Decimal(str(obj))
    if isinstance(obj, dict):  return {k: convert_numbers_for_dynamodb(v) for k, v in obj.items()}
    if isinstance(obj, list):  return [convert_numbers_for_dynamodb(v) for v in obj]
    return obj


# ============================================================
# Event dataclass + normalisation
# ============================================================

@dataclass
class Event:
    event_id:       str
    event_time_str: str
    event_time:     Optional[datetime]
    day_bucket:     str
    aws_region:     str
    event_name:     str
    event_source:   str
    actor:          str
    source_ip:      str
    error_code:     str
    error_message:  str
    raw:            Dict[str, Any]


def normalize_items(raw_items: List[Dict[str, Any]]) -> List[Event]:
    out: List[Event] = []
    for it in raw_items:
        try:
            event_time_str = str(it.get("eventTime") or "")
            event_time     = parse_iso8601(event_time_str)
            day_bucket     = str(it.get("day_bucket") or "")
            if not day_bucket and event_time:
                day_bucket = event_time.date().isoformat()
            ev_obj        = safe_json_loads(it.get("event_json") or "")
            out.append(Event(
                event_id       = str(it.get("event_id") or it.get("eventID") or it.get("id") or ""),
                event_time_str = event_time_str,
                event_time     = event_time,
                day_bucket     = day_bucket,
                aws_region     = str(it.get("awsRegion")       or "unknown"),
                event_name     = str(it.get("eventName")       or "unknown"),
                event_source   = str(it.get("eventSource")     or "unknown"),
                actor          = str(it.get("actor")           or "unknown"),
                source_ip      = str(it.get("sourceIPAddress") or "unknown"),
                error_code     = str(ev_obj.get("errorCode")    or "") if ev_obj else "",
                error_message  = str(ev_obj.get("errorMessage") or "") if ev_obj else "",
                raw            = it,
            ))
        except Exception as exc:
            log.warning("Skipping malformed event: %s", exc)
    out.sort(key=lambda e: e.event_time or datetime(1970, 1, 1, tzinfo=timezone.utc))
    return out


# ============================================================
# DynamoDB I/O
# ============================================================

def scan_source_table(lookback_days: int) -> List[Dict[str, Any]]:
    table       = _ddb.Table(SOURCE_TABLE)
    cutoff_day  = (utc_now() - timedelta(days=lookback_days)).date().isoformat()
    filter_expr = Attr("day_bucket").gte(cutoff_day)
    items: List[Dict[str, Any]] = []
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"FilterExpression": filter_expr}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp     = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    log.info("Scanned %d events (cutoff %s)", len(items), cutoff_day)
    return items


def fetch_existing_ids() -> Set[str]:
    table    = _ddb.Table(DEST_TABLE)
    existing: Set[str] = set()
    last_key = None
    while True:
        kwargs: Dict[str, Any] = {"ProjectionExpression": "incident_id"}
        if last_key:
            kwargs["ExclusiveStartKey"] = last_key
        resp     = table.scan(**kwargs)
        for item in resp.get("Items", []):
            iid = item.get("incident_id")
            if iid:
                existing.add(str(iid))
        last_key = resp.get("LastEvaluatedKey")
        if not last_key:
            break
    return existing


def write_new_incidents(incidents: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Atomic skip-if-exists via ConditionExpression — no duplicates possible."""
    if not incidents:
        return 0, 0
    table = _ddb.Table(DEST_TABLE)
    written = skipped = 0
    for incident in incidents:
        iid = str(incident.get("incident_id") or "")
        if not iid:
            continue
        safe_item               = convert_numbers_for_dynamodb(incident)
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
    return written, skipped


# ============================================================
# Detection
# ============================================================

SENSITIVE_IAM = {
    "createuser", "createaccesskey", "putuserpolicy", "attachuserpolicy",
    "attachgrouppolicy", "attachrolepolicy", "addusertogroup",
    "updateloginprofile", "createpolicy", "createpolicyversion",
    "setdefaultpolicyversion", "passrole", "updateassumerolepolicy", "putrolepolicy",
}


def is_denied(e: Event) -> bool:
    c = (e.error_code or "").lower()
    return "accessdenied" in c or "unauthorized" in c


def is_invalid_ami(e: Event) -> bool:
    return ((e.event_name or "").lower() == "runinstances"
            and (e.error_code or "").lower() == "invalidamiid.malformed")


def is_signin_failure(e: Event) -> bool:
    src  = (e.event_source or "").lower()
    name = (e.event_name   or "").lower()
    code = (e.error_code   or "").lower()
    return ("signin.amazonaws.com" in src
            or name in {"consolelogin", "credentialchallenge"}
            or "failedauthentication" in code
            or ("invalid" in code and "token" in code))


def build_minute_bins(events: List[Event], start: datetime, end: datetime) -> Dict[datetime, List[Event]]:
    bins: Dict[datetime, List[Event]] = {}
    for e in events:
        if not e.event_time or e.event_time < start or e.event_time > end:
            continue
        bins.setdefault(minute_bucket(e.event_time), []).append(e)
    return bins


def compute_baseline_threshold(series: List[int], hard_min: int, multiplier: float = 3.0) -> int:
    if not series:
        return hard_min
    s  = sorted(series)
    n  = len(s)
    q1 = s[n // 4]; q3 = s[(3 * n) // 4]
    return max(hard_min, int(s[n // 2] + multiplier * max(0, q3 - q1)))


def compact_samples(events: List[Event], max_samples: int = 6) -> List[Dict[str, Any]]:
    return [{
        "eventTime":       e.event_time_str,
        "awsRegion":       e.aws_region,
        "eventName":       e.event_name,
        "eventSource":     e.event_source,
        "actor":           e.actor,
        "sourceIPAddress": e.source_ip,
        "errorCode":       e.error_code,
        "errorMessage":    (e.error_message[:220] + "…") if len(e.error_message) > 220 else e.error_message,
    } for e in events[:max_samples]]


def incident_primary_key(inc_type: str, evidence: Dict[str, Any]) -> str:
    if isinstance(evidence, dict):
        by_actor = evidence.get("by_actor")
        if isinstance(by_actor, dict) and by_actor:
            top_actor = next(iter(by_actor.keys()))
            if top_actor: return f"actor:{top_actor}"
        peak = evidence.get("peak_actor")
        if isinstance(peak, str) and peak: return f"actor:{peak}"
        regions = evidence.get("new_regions")
        if isinstance(regions, list) and regions:
            return "regions:" + ",".join(sorted(str(r) for r in regions))
    return "unknown"


def make_incident(*, inc_type, severity, title, first_seen, last_seen,
                  count, evidence, samples, recommendation, is_new, now) -> Dict[str, Any]:
    fs          = iso_z(first_seen)
    ls          = iso_z(last_seen)
    primary     = incident_primary_key(inc_type, evidence)
    incident_id = stable_hash16(f"v1|{inc_type}|{fs}|{ls}|{primary}|{REGION}")
    return {
        "incident_id": incident_id, "type": inc_type, "severity": severity,
        "title": title, "first_seen": fs, "last_seen": ls,
        "age": human_age(now, last_seen), "count": count,
        "evidence_count": count, "sample_count": len(samples),
        "is_new": is_new, "evidence": evidence,
        "samples": samples, "recommendation": recommendation,
    }


def detect_spike_family(events: List[Event], *, now: datetime, window_minutes: int,
                        inc_type: str, title_prefix: str, match_fn,
                        hard_min_threshold: int, sev_medium: int, sev_high: int,
                        recommendation: str) -> List[Dict[str, Any]]:
    ev = [e for e in events if e.event_time]
    if not ev: return []
    start = ev[0].event_time; end = ev[-1].event_time  # type: ignore
    matched = [e for e in ev if match_fn(e)]
    if not matched: return []

    min_bins    = build_minute_bins(matched, start, end)
    all_minutes = sorted(min_bins.keys())
    threshold   = compute_baseline_threshold([len(min_bins[m]) for m in all_minutes], hard_min_threshold)
    window      = timedelta(minutes=window_minutes)

    flagged: List[Tuple[datetime, datetime, int, List[Event]]] = []
    for anchor in all_minutes:
        w_end = anchor + window
        wevs: List[Event] = []; cnt = 0
        for m in all_minutes:
            if m < anchor: continue
            if m > w_end:  break
            cnt += len(min_bins.get(m, []))
            wevs.extend(min_bins.get(m, []))
        if cnt >= threshold:
            flagged.append((anchor, w_end, cnt, wevs))

    if not flagged: return []

    flagged.sort(key=lambda x: x[0])
    clusters: List[Tuple[datetime, datetime, List[Event]]] = []
    cur_s, cur_e, _, cur_set = flagged[0]; cur_set = list(cur_set)
    for w_s, w_e, _, w_evs in flagged[1:]:
        if w_s <= cur_e:
            if w_e > cur_e: cur_e = w_e
            cur_set.extend(w_evs)
        else:
            clusters.append((cur_s, cur_e, cur_set))
            cur_s, cur_e, cur_set = w_s, w_e, list(w_evs)
    clusters.append((cur_s, cur_e, cur_set))

    incidents: List[Dict[str, Any]] = []
    for s, e, cevents in clusters:
        seen: set = set(); dedup: List[Event] = []
        for x in sorted(cevents, key=lambda z: z.event_time or utc_now()):
            if x.event_id and x.event_id in seen: continue
            if x.event_id: seen.add(x.event_id)
            dedup.append(x)
        if not dedup: continue
        first_seen = dedup[0].event_time or s
        last_seen  = dedup[-1].event_time or e
        count      = len(dedup)
        incidents.append(make_incident(
            inc_type=inc_type, severity=severity_scale(count, sev_medium, sev_high),
            title=f"{title_prefix}: {count} events",
            first_seen=first_seen, last_seen=last_seen, count=count,
            evidence={
                "window_minutes": window_minutes, "auto_threshold": threshold,
                "by_actor":    top_n(count_by([x.actor      for x in dedup])),
                "by_region":   top_n(count_by([x.aws_region for x in dedup])),
                "by_eventName": top_n(count_by([x.event_name for x in dedup])),
            },
            samples=compact_samples(dedup),
            recommendation=recommendation, is_new=True, now=now,
        ))
    return incidents


def detect_new_region_usage(events: List[Event], *, now: datetime) -> List[Dict[str, Any]]:
    ev = [e for e in events if e.event_time]
    if not ev: return []
    start = ev[0].event_time; end = ev[-1].event_time  # type: ignore
    baseline_end     = start + timedelta(days=7)
    baseline_regions = sorted({e.aws_region for e in ev if e.event_time and e.event_time <= baseline_end})
    later            = [e for e in ev if e.event_time and e.event_time > baseline_end]
    new_regions      = sorted({e.aws_region for e in later if e.aws_region not in baseline_regions})
    if not new_regions: return []
    hits = sorted([e for e in later if e.aws_region in new_regions], key=lambda x: x.event_time or utc_now())
    return [make_incident(
        inc_type="new_region_activity",
        severity="high" if len(new_regions) >= 3 else "medium",
        title=f"New region(s) used: {', '.join(new_regions)}",
        first_seen=hits[0].event_time or start, last_seen=hits[-1].event_time or end,
        count=len(hits),
        evidence={
            "baseline_regions": baseline_regions, "new_regions": new_regions,
            "by_actor":     top_n(count_by([e.actor      for e in hits])),
            "by_eventName": top_n(count_by([e.event_name for e in hits])),
        },
        samples=compact_samples(hits),
        recommendation="If those regions aren't expected, investigate credential use and consider region guardrails.",
        is_new=True, now=now,
    )]


def detect_api_burst_actor(events: List[Event], *, now: datetime, window_minutes: int) -> List[Dict[str, Any]]:
    ev = [e for e in events if e.event_time]
    if not ev: return []
    start = ev[0].event_time; end = ev[-1].event_time  # type: ignore
    all_bins = build_minute_bins(ev, start, end)
    minutes  = sorted(all_bins.keys())
    if not minutes: return []

    window = timedelta(minutes=window_minutes)
    maxima: List[int] = []
    max_detail: List[Tuple[datetime, datetime, str, int, List[Event]]] = []
    for anchor in minutes:
        w_end = anchor + window
        bkts: List[Event] = []
        for m in minutes:
            if m < anchor: continue
            if m > w_end:  break
            bkts.extend(all_bins.get(m, []))
        if not bkts: continue
        counts = count_by([e.actor for e in bkts])
        top_actor, top_count = next(iter(counts.items()))
        maxima.append(top_count)
        max_detail.append((anchor, w_end, top_actor, top_count, bkts))

    threshold = compute_baseline_threshold(maxima, hard_min=300)
    flagged   = [(s, e, a, c, evs) for (s, e, a, c, evs) in max_detail if c >= threshold]
    if not flagged: return []

    flagged.sort(key=lambda x: x[0])
    clusters: List[Tuple[datetime, datetime, List[Tuple[str, int]], List[Event]]] = []
    cur_s, cur_e, cur_a, cur_c, cur_evs = flagged[0]
    cur_peaks: List[Tuple[str, int]] = [(cur_a, cur_c)]; cur_events = list(cur_evs)
    for s, e, a, c, evs in flagged[1:]:
        if s <= cur_e:
            if e > cur_e: cur_e = e
            cur_peaks.append((a, c)); cur_events.extend(evs)
        else:
            clusters.append((cur_s, cur_e, cur_peaks, cur_events))
            cur_s, cur_e, cur_peaks, cur_events = s, e, [(a, c)], list(evs)
    clusters.append((cur_s, cur_e, cur_peaks, cur_events))

    incidents: List[Dict[str, Any]] = []
    for s, e, peaks, cevs in clusters:
        cevs = sorted([x for x in cevs if x.event_time], key=lambda x: x.event_time or utc_now())
        if not cevs: continue
        peaks_sorted           = sorted(peaks, key=lambda t: t[1], reverse=True)
        peak_actor, peak_count = peaks_sorted[0]
        incidents.append(make_incident(
            inc_type="api_burst",
            severity=severity_scale(peak_count, medium=600, high=1200),
            title=f"API burst: '{peak_actor}' peaked at {peak_count} calls/{window_minutes}m",
            first_seen=cevs[0].event_time or s, last_seen=cevs[-1].event_time or e,
            count=len(cevs),
            evidence={
                "window_minutes": window_minutes, "auto_threshold": threshold,
                "peak_actor": peak_actor, "peak_count": peak_count,
                "top_actors_in_cluster": peaks_sorted[:5],
                "by_eventName": top_n(count_by([x.event_name for x in cevs])),
                "by_region":    top_n(count_by([x.aws_region for x in cevs])),
            },
            samples=compact_samples([x for x in cevs if x.actor == peak_actor] or cevs),
            recommendation="Confirm whether this actor is expected automation. If not, investigate scripted abuse or compromised creds.",
            is_new=True, now=now,
        ))
    return incidents


# ============================================================
# Conversion (same logic as pipeline script)
# ============================================================

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
    count_i  = max(0, to_int(count, 0))
    ev: Dict[str, Any] = evidence if isinstance(evidence, dict) else {}
    auto_thr = to_int(ev.get("auto_threshold"), 0) or \
               {"access_denied_spike": 5, "suspicious_iam_activity": 3, "api_burst": 300}.get(det_type, 5)

    if det_type == "access_denied_spike":
        base = int(round(20 + 15 * count_i / max(auto_thr, 1)))
    elif det_type == "api_burst":
        base = int(round(30 + 20 * to_int(ev.get("peak_count"), count_i) / max(auto_thr, 1)))
    elif det_type == "suspicious_iam_activity":
        base = int(round(25 + 8 * count_i + 4 * len(ev.get("by_eventName") or {})))
    elif det_type == "new_region_activity":
        base = 50 + 15 * max(0, len(ev.get("new_regions") or []) - 1)
    elif det_type in ("signin_failure_spike", "invalid_ami_spike"):
        base = 20 + 12 * count_i
    else:
        base = int(round(20 + 10 * count_i / max(auto_thr, 1)))

    return clamp(max(clamp(base), severity_floor(severity)))


def _generate_incident_id(det_inc: Dict[str, Any], detected_at: Optional[str]) -> str:
    """Stable ID — detected_at NOT in hash so it never changes between runs."""
    fingerprint = "|".join([
        str(det_inc.get("type")       or ""),
        str(det_inc.get("first_seen") or ""),
        str(det_inc.get("last_seen")  or ""),
        str(det_inc.get("severity")   or ""),
    ])
    h           = hashlib.sha1(fingerprint.encode()).hexdigest()[:6]
    ts          = det_inc.get("first_seen") or detected_at or ""
    date_prefix = ts[:10].replace("-", "") if len(ts) >= 10 else ""
    return f"inc_{date_prefix}_{h}"


def convert_one(det_inc: Dict[str, Any], detected_at: Optional[str]) -> Dict[str, Any]:
    det_type = str(det_inc.get("type")     or "unknown")
    severity = str(det_inc.get("severity") or "low").lower()
    evidence = det_inc.get("evidence") or {}
    samples  = det_inc.get("samples")  or []

    by_actor: Dict[str, int] = {}
    if isinstance(evidence, dict) and isinstance(evidence.get("by_actor"), dict):
        by_actor = evidence["by_actor"]
    actor = (max(by_actor.items(), key=lambda kv: kv[1])[0] if by_actor
             else (samples[0].get("actor") if samples else None) or "unknown")

    count       = to_int(det_inc.get("count"), 0)
    rule_score  = score_incident(det_type, severity, count, evidence)
    ts_start    = det_inc.get("first_seen")
    ts_end      = det_inc.get("last_seen")
    dt_detected = parse_iso8601_z(detected_at)
    dt_end      = parse_iso8601_z(ts_end) or parse_iso8601_z(ts_start)
    age_seconds: Optional[int] = (
        max(0, int((dt_detected - dt_end).total_seconds()))
        if dt_detected and dt_end else None
    )

    return {
        "incident_id":        _generate_incident_id(det_inc, detected_at),
        "incident_type":      map_incident_type(det_type),
        "actor":              actor,
        "by_actor":           by_actor,
        "timestamp_start":    ts_start,
        "timestamp_end":      ts_end,
        "timestamp_detected": detected_at,
        "age_seconds":        age_seconds,
        "is_new":             bool(det_inc.get("is_new", False)),
        "severity":           severity,
        "rule_score":         rule_score,
        "final_risk_score":   rule_score,
        "triggered_features": map_triggered_features(det_type),
        "explanation": {
            "summary":        det_inc.get("title")          or det_type,
            "recommendation": det_inc.get("recommendation") or "",
        },
        "evidence": {
            "count":           count,
            "by_actor":        by_actor,
            "window_minutes":  evidence.get("window_minutes") if isinstance(evidence, dict) else None,
            "window_seconds":  to_int(evidence.get("window_minutes"), 0) * 60
                               if isinstance(evidence, dict) else None,
            "top_event_names": list((evidence.get("by_eventName") or {}).keys())[:5]
                               if isinstance(evidence, dict) else [],
        },
    }


# ============================================================
# Lambda entrypoint
# ============================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda handler invoked every 5 minutes by EventBridge Scheduler.
    `event` and `context` are standard Lambda params; config comes from env vars.
    """
    run_start = utc_now()
    log.info("AnomAI pipeline starting — source=%s dest=%s lookback=%dd",
             SOURCE_TABLE, DEST_TABLE, LOOKBACK_DAYS)

    try:
        # 1. Scan events
        raw_items = scan_source_table(LOOKBACK_DAYS)
        events    = normalize_items(raw_items)
        now       = utc_now()

        if not events:
            log.info("No events in lookback window — nothing to write.")
            return {"statusCode": 200, "body": "no_events"}

        # 2. Run all detectors
        wm = DETECT_WINDOW_MINUTES
        incidents: List[Dict[str, Any]] = []
        incidents.extend(detect_spike_family(events, now=now, window_minutes=wm,
            inc_type="access_denied_spike", title_prefix="AccessDenied/Unauthorized spike",
            match_fn=is_denied, hard_min_threshold=5, sev_medium=10, sev_high=25,
            recommendation="Verify the failing principal is expected. If not, investigate credential misuse or broken automation; tighten IAM and add alerts."))
        incidents.extend(detect_spike_family(events, now=now, window_minutes=wm,
            inc_type="suspicious_iam_activity", title_prefix="Sensitive IAM activity spike",
            match_fn=lambda e: (e.event_name or "").lower() in SENSITIVE_IAM,
            hard_min_threshold=3, sev_medium=8, sev_high=20,
            recommendation="Review IAM changes. If unexpected, check surrounding CloudTrail events and lock down privilege-escalation paths."))
        incidents.extend(detect_spike_family(events, now=now, window_minutes=wm,
            inc_type="invalid_ami_spike", title_prefix="EC2 invalid AMI attempts",
            match_fn=is_invalid_ami, hard_min_threshold=1, sev_medium=5, sev_high=15,
            recommendation="Could be broken automation or probing. Verify who attempted RunInstances and whether it was intended."))
        incidents.extend(detect_spike_family(events, now=now, window_minutes=wm,
            inc_type="signin_failure_spike", title_prefix="Sign-in/auth failures spike",
            match_fn=is_signin_failure, hard_min_threshold=3, sev_medium=6, sev_high=15,
            recommendation="Investigate sign-in failure sources and actors. If unexpected, reset credentials and verify MFA/Identity Center settings."))
        incidents.extend(detect_new_region_usage(events, now=now))
        incidents.extend(detect_api_burst_actor(events, now=now, window_minutes=wm))

        # 3. Dedup by stable detector-side ID
        dedup_map: Dict[str, Dict[str, Any]] = {}
        for inc in incidents:
            iid = str(inc.get("incident_id") or "")
            if not iid: continue
            prev = dedup_map.get(iid)
            if not prev or str(inc.get("last_seen") or "") > str(prev.get("last_seen") or ""):
                dedup_map[iid] = inc
        incidents = list(dedup_map.values())

        # 4. Convert to API schema
        detected_at = iso_z(now)
        converted   = [convert_one(inc, detected_at) for inc in incidents]

        # 5. Determine which are genuinely new
        existing_ids = fetch_existing_ids()
        new_to_write: List[Dict[str, Any]] = []
        for inc in converted:
            iid = str(inc.get("incident_id") or "")
            if iid in existing_ids:
                inc["is_new"] = False
            else:
                inc["is_new"] = True
                new_to_write.append(inc)

        # 6. Write new incidents (conditional put — no duplicates)
        written, skipped = write_new_incidents(new_to_write)

        elapsed = (utc_now() - run_start).total_seconds()
        log.info("Done — events=%d detected=%d new=%d skipped=%d elapsed=%.1fs",
                 len(events), len(converted), written, skipped, elapsed)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "events_scanned":     len(events),
                "incidents_detected": len(converted),
                "new_written":        written,
                "skipped_existing":   skipped,
                "elapsed_seconds":    round(elapsed, 1),
            }),
        }

    except Exception as exc:
        log.exception("Pipeline failed: %s", exc)
        raise  # Let Lambda mark the invocation as failed so CloudWatch alerts fire