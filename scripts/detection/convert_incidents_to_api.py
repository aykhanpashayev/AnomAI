#!/usr/bin/env python3
"""
Convert detector output (out/incidents.json) into the MVP "Incident Object" schema
defined in research/api/schema.json.

Input:  out/incidents.json  (your current detector output wrapper)
Output: out/incidents_api.json  (list of incident objects, UI/API-friendly)

Run:
  python3 scripts/detection/convert_incidents_to_api.py
  python3 scripts/detection/convert_incidents_to_api.py --in out/incidents.json --out out/incidents_api.json
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional


DEFAULT_IN = "out/incidents.json"
DEFAULT_OUT = "out/incidents_api.json"


def get_arg(flag: str) -> Optional[str]:
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)


def top_key(d: Any) -> str:
    """Return first key of a dict (already sorted by your detector), else 'unknown'."""
    if isinstance(d, dict) and d:
        return str(next(iter(d.keys())))
    return "unknown"


def map_incident_type(det_type: str) -> str:
    m = {
        "access_denied_spike": "AccessDeniedSpike",
        "suspicious_iam_activity": "SensitiveIAMSpike",
        "new_region_activity": "NewRegion",
        "api_burst": "APIBurst",
        "invalid_ami_spike": "InvalidAMISpike",
        "signin_failure_spike": "SigninFailureSpike",
    }
    return m.get(det_type, det_type)


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


def score_from_severity(sev: str) -> int:
    # MVP-simple and deterministic (replace later with real scoring)
    sev = (sev or "").lower()
    if sev == "high":
        return 85
    if sev == "medium":
        return 60
    return 30


def convert_one(det_inc: Dict[str, Any]) -> Dict[str, Any]:
    det_type = str(det_inc.get("type") or "unknown")
    severity = str(det_inc.get("severity") or "low").lower()

    evidence = det_inc.get("evidence") or {}
    by_actor = evidence.get("by_actor") if isinstance(evidence, dict) else None

    actor = top_key(by_actor)

    # timestamps
    ts_start = str(det_inc.get("first_seen") or "")
    ts_end = str(det_inc.get("last_seen") or "")

    # basic scoring (MVP)
    rule_score = score_from_severity(severity)
    final_risk_score = rule_score

    # evidence mapping to schema.json (optional fields allowed)
    window_minutes = None
    if isinstance(evidence, dict):
        window_minutes = evidence.get("window_minutes")

    window_seconds = None
    if isinstance(window_minutes, (int, float)):
        window_seconds = int(window_minutes * 60)

    top_event_names: List[str] = []
    if isinstance(evidence, dict):
        by_event = evidence.get("by_eventName")
        if isinstance(by_event, dict):
            top_event_names = [str(k) for k in list(by_event.keys())[:10]]

    out: Dict[str, Any] = {
        "incident_id": str(det_inc.get("incident_id") or ""),  # already deterministic from detector
        "incident_type": map_incident_type(det_type),
        "actor": actor,
        "timestamp_start": ts_start,
        "timestamp_end": ts_end,
        "severity": severity,
        "rule_score": rule_score,
        "final_risk_score": final_risk_score,
        "triggered_features": map_triggered_features(det_type),
        "explanation": {
            "summary": str(det_inc.get("title") or "Anomaly detected."),
            "recommendation": str(det_inc.get("recommendation") or ""),
        },
        "evidence": {
            # These keys are optional in schema.json; we set what we can safely.
            "access_denied_count": det_inc.get("count") if det_type == "access_denied_spike" else None,
            "window_seconds": window_seconds,
            "top_event_names": top_event_names,
        },
    }

    # Clean Nones from evidence for nicer output
    ev = out.get("evidence", {})
    if isinstance(ev, dict):
        out["evidence"] = {k: v for k, v in ev.items() if v is not None}

    return out


def validate_required(obj: Dict[str, Any]) -> List[str]:
    required = [
        "incident_id",
        "incident_type",
        "actor",
        "timestamp_start",
        "timestamp_end",
        "severity",
        "rule_score",
        "final_risk_score",
        "triggered_features",
        "explanation",
    ]
    missing = []
    for k in required:
        if k not in obj:
            missing.append(k)
    # minimal nested check
    if "explanation" in obj and isinstance(obj["explanation"], dict):
        if "summary" not in obj["explanation"]:
            missing.append("explanation.summary")
    return missing


def main() -> int:
    in_path = (get_arg("--in") or DEFAULT_IN).strip()
    out_path = (get_arg("--out") or DEFAULT_OUT).strip()

    if not os.path.exists(in_path):
        print(f"[ERROR] Input not found: {in_path}")
        return 2

    with open(in_path, "r", encoding="utf-8") as f:
        wrapper = json.load(f)

    det_incidents = wrapper.get("incidents") if isinstance(wrapper, dict) else None
    if not isinstance(det_incidents, list):
        print("[ERROR] Input file does not look like detector output wrapper with key 'incidents'.")
        return 2

    api_incidents: List[Dict[str, Any]] = []
    for det in det_incidents:
        if not isinstance(det, dict):
            continue
        api_obj = convert_one(det)
        missing = validate_required(api_obj)
        if missing:
            print(f"[WARN] Converted incident missing required fields: {missing} (incident_id={api_obj.get('incident_id')})")
        api_incidents.append(api_obj)

    ensure_parent_dir(out_path)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(api_incidents, f, indent=2)

    print(f"[OK] Wrote {out_path} (count={len(api_incidents)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())