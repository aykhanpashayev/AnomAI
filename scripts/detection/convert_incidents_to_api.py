#!/usr/bin/env python3
"""
Convert detector output (out/incidents.json) into the MVP "Incident Object"
schema defined in research/api/schema.json.

Input:
  out/incidents.json  (detector output)

Output:
  out/incidents_api.json  (list of Incident Objects for Risk API / UI)

Supports:
  - CLI flags: --in, --out
  - Env vars: ANOMAI_INCIDENTS_IN, ANOMAI_INCIDENTS_OUT
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DEFAULT_INPUT_PATH = "out/incidents.json"
DEFAULT_OUTPUT_PATH = "out/incidents_api.json"


# ------------------------------------------------------------
# Utility helpers
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
        if not s:
            return default
        return int(float(s))
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
    """
    Parse timestamps like:
      2026-02-16T20:36:34.871105Z
      2026-02-03T14:23:51Z
    Returns an aware datetime in UTC or None if invalid.
    """
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


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


# ------------------------------------------------------------
# Triggered feature mapping
# ------------------------------------------------------------

def map_triggered_features(det_type: str) -> List[str]:
    m = {
        "access_denied_spike": ["ExcessiveAccessDenied"],
        "suspicious_iam_activity": ["SensitiveIAMActions"],
        "new_region_activity": ["FirstTimeRegionUse"],
        "api_burst": ["APIBurst"],
        "invalid_ami_spike": ["InvalidAMI"],
        "signin_failure_spike": ["SigninFailureSpike"],
    }
    return m.get(det_type, ["AnomalyDetected"])


# ------------------------------------------------------------
# Incident type mapping
# ------------------------------------------------------------

def map_incident_type(det_type: str) -> str:
    m = {
        "access_denied_spike": "AccessDeniedSpike",
        "suspicious_iam_activity": "SensitiveIAMSpike",
        "api_burst": "APIBurst",
        "new_region_activity": "NewRegion",
        "signin_failure_spike": "SigninFailureSpike",
        "invalid_ami_spike": "InvalidAMISpike",
    }
    return m.get(det_type, "Anomaly")


# ------------------------------------------------------------
# Evidence-aware rule scoring (MVP but realistic)
# ------------------------------------------------------------

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


# ------------------------------------------------------------
# Conversion
# ------------------------------------------------------------

def _generate_incident_id(det_inc: Dict[str, Any], detected_at: Optional[str]) -> str:
    """
    Generate a stable, unique incident ID from key fields when one is not
    already present in the detector output.
    Format: inc_<YYYYMMDD>_<6-char hash>
    """
    raw = det_inc.get("incident_id")
    if raw is not None:
        return str(raw)

    fingerprint = "|".join([
        str(det_inc.get("type") or ""),
        str(det_inc.get("first_seen") or ""),
        str(det_inc.get("last_seen") or ""),
        str(det_inc.get("severity") or ""),
        str(detected_at or ""),
    ])
    h = hashlib.sha1(fingerprint.encode()).hexdigest()[:6]

    date_prefix = ""
    ts = det_inc.get("first_seen") or detected_at or ""
    if len(ts) >= 10:
        date_prefix = ts[:10].replace("-", "")

    return f"inc_{date_prefix}_{h}"


def convert_one(det_inc: Dict[str, Any], detected_at: Optional[str]) -> Dict[str, Any]:
    det_type = str(det_inc.get("type") or "unknown")
    severity = str(det_inc.get("severity") or "low").lower()

    evidence = det_inc.get("evidence") or {}
    samples = det_inc.get("samples") or []

    # Preserve full by_actor dict for the UI (multi-actor support)
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

    count = to_int(det_inc.get("count"), 0)
    rule_score = score_incident(det_type, severity, count, evidence)
    final_risk_score = rule_score

    ts_start = det_inc.get("first_seen")
    ts_end = det_inc.get("last_seen")
    is_new = bool(det_inc.get("is_new", False))

    # age_seconds = detected_at - timestamp_end (fallback to timestamp_start)
    age_seconds: Optional[int] = None
    dt_detected = parse_iso8601_z(detected_at)
    dt_end = parse_iso8601_z(ts_end) or parse_iso8601_z(ts_start)
    if dt_detected and dt_end:
        delta = dt_detected - dt_end
        age_seconds = max(0, int(delta.total_seconds()))

    api_obj = {
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
            "window_minutes": evidence.get("window_minutes") if isinstance(evidence, dict) else None,
            "window_seconds": (
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

    return api_obj


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--in", dest="in_path", default=os.getenv("ANOMAI_INCIDENTS_IN", DEFAULT_INPUT_PATH))
    p.add_argument("--out", dest="out_path", default=os.getenv("ANOMAI_INCIDENTS_OUT", DEFAULT_OUTPUT_PATH))
    return p.parse_args()


def main() -> int:
    args = parse_args()
    in_path = args.in_path
    out_path = args.out_path

    if not os.path.exists(in_path):
        print(f"[ERROR] Missing {in_path}", file=sys.stderr)
        return 1

    with open(in_path, "r") as f:
        data = json.load(f)

    detected_at = data.get("generated_at") if isinstance(data, dict) else None
    incidents = data.get("incidents", []) if isinstance(data, dict) else []

    converted = [convert_one(i, detected_at) for i in incidents]

    ensure_parent_dir(out_path)
    with open(out_path, "w") as f:
        json.dump(converted, f, indent=2)

    print(f"[OK] Read {in_path} | Wrote {out_path} (count={len(converted)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
