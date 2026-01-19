#!/usr/bin/env python3
import argparse
import gzip
import json
import os
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------- Helpers: safe getters + identity parsing ----------

def deep_get(d: Dict[str, Any], path: List[str], default=None):
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return cur if cur is not None else default


def parse_assumed_role_arn(user_arn: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """
    For assumed-role ARN format:
      arn:aws:sts::<acct>:assumed-role/<roleName>/<sessionName>
    Returns (roleName, sessionName).
    """
    if not user_arn or ":assumed-role/" not in user_arn:
        return None, None
    try:
        after = user_arn.split(":assumed-role/")[1]
        parts = after.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
    except Exception:
        pass
    return None, None


def mask_access_key(access_key_id: Optional[str], keep_last: int = 4) -> Optional[str]:
    if not access_key_id:
        return None
    if len(access_key_id) <= keep_last:
        return "*" * len(access_key_id)
    return "*" * (len(access_key_id) - keep_last) + access_key_id[-keep_last:]


def load_json(path: str) -> Dict[str, Any]:
    if path.endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_mfa(value: Any) -> Optional[bool]:
    """
    CloudTrail often provides mfaAuthenticated as "true"/"false" (string).
    Normalize to boolean when possible.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v == "true":
            return True
        if v == "false":
            return False
        return None
    # unknown type
    return None


# ---------- Normalization (fields you care about) ----------

def normalize_record(
    record: Dict[str, Any],
    *,
    mask_keys: bool = True,
    drop_heavy_fields: bool = False,
) -> Dict[str, Any]:
    user_identity = record.get("userIdentity", {}) or {}
    user_arn = user_identity.get("arn")

    role_name, session_name = parse_assumed_role_arn(user_arn)

    access_key = user_identity.get("accessKeyId")
    if mask_keys:
        access_key = mask_access_key(access_key)

    principal_id = user_identity.get("principalId") or ""
    principal_suffix = principal_id.split(":")[-1] if ":" in principal_id else None

    # IAM username (only when it's truly there)
    iam_user_name = user_identity.get("userName")

    # Best "actor" field for AnomAI (who is doing the action)
    # Priority: IAM userName -> assumed-role sessionName -> principalId suffix -> ARN fallback
    actor = (
        iam_user_name
        or session_name
        or principal_suffix
        or user_arn
    )

    # mfaAuthenticated (normalize to bool)
    mfa_raw = deep_get(user_identity, ["sessionContext", "attributes", "mfaAuthenticated"])
    mfa_authenticated = normalize_mfa(mfa_raw)

    # Optional heavy fields
    request_params = None if drop_heavy_fields else record.get("requestParameters")
    response_elements = None if drop_heavy_fields else record.get("responseElements")

    normalized = {
        # Identity
        "userType": user_identity.get("type"),
        "userArn": user_arn,
        "accountId": user_identity.get("accountId"),
        "principalId": principal_id or None,
        "accessKeyId": access_key,
        "sessionIssuerArn": deep_get(user_identity, ["sessionContext", "sessionIssuer", "arn"]),
        "roleName": role_name,
        "sessionName": session_name,

        # Identity (normalized)
        "userName": iam_user_name,   # only populated for IAM users
        "actor": actor,              # best-effort who performed the action
        "mfaAuthenticated": mfa_authenticated,

        # Core event info
        "eventName": record.get("eventName"),
        "eventSource": record.get("eventSource"),
        "eventType": record.get("eventType"),
        "readOnly": record.get("readOnly"),
        "awsRegion": record.get("awsRegion"),
        "eventTime": record.get("eventTime"),
        "eventID": record.get("eventID"),
        "requestID": record.get("requestID"),

        # Network/client
        "sourceIPAddress": record.get("sourceIPAddress"),
        "userAgent": record.get("userAgent"),
        "vpcEndpointId": record.get("vpcEndpointId"),

        # Errors / security context
        "errorCode": record.get("errorCode"),
        "errorMessage": record.get("errorMessage"),
        "additionalEventData": record.get("additionalEventData"),
        "tlsDetails": record.get("tlsDetails"),

        # Optional payloads
        "requestParameters": request_params,
        "responseElements": response_elements,
    }

    return normalized


# ---------- Input discovery (file or folder) ----------

def iter_input_files(input_path: str) -> Iterable[str]:
    if os.path.isfile(input_path):
        yield input_path
        return

    for root, _, files in os.walk(input_path):
        for name in files:
            if name.endswith(".json") or name.endswith(".json.gz"):
                yield os.path.join(root, name)


# ---------- Main parsing loop ----------

def parse_cloudtrail_file(
    path: str,
    *,
    mask_keys: bool,
    drop_heavy_fields: bool,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        data = load_json(path)
        records = data.get("Records", [])
        if not isinstance(records, list):
            return [], f"{path}: 'Records' is not a list"

        normalized = []
        for rec in records:
            if isinstance(rec, dict):
                normalized.append(
                    normalize_record(rec, mask_keys=mask_keys, drop_heavy_fields=drop_heavy_fields)
                )
        return normalized, None
    except Exception as e:
        return [], f"{path}: {e}"


def write_jsonl(events: Iterable[Dict[str, Any]], out_path: str) -> int:
    count = 0
    with open(out_path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
            count += 1
    return count


def print_summary(
    total: int,
    errors: List[str],
    top_sources: Counter,
    top_names: Counter,
    top_actors: Counter,
):
    print("\n--- Summary ---")
    print(f"Total normalized events: {total}")
    print(f"Files with errors: {len(errors)}")
    if errors:
        print("First 5 errors:")
        for err in errors[:5]:
            print(f"  - {err}")

    print("\nTop eventSource:")
    for k, v in top_sources.most_common(10):
        print(f"  {k}: {v}")

    print("\nTop eventName:")
    for k, v in top_names.most_common(10):
        print(f"  {k}: {v}")

    print("\nTop actor:")
    for k, v in top_actors.most_common(10):
        print(f"  {k}: {v}")


def main():
    parser = argparse.ArgumentParser(
        description="Parse AWS CloudTrail logs (.json or .json.gz) into normalized JSONL."
    )
    parser.add_argument("input", help="Path to a CloudTrail file OR a folder containing CloudTrail logs")
    parser.add_argument("-o", "--out", default="normalized.jsonl", help="Output JSONL file path")
    parser.add_argument("--no-mask-keys", action="store_true", help="Do NOT mask accessKeyId (not recommended)")
    parser.add_argument("--drop-heavy-fields", action="store_true",
                        help="Drop requestParameters/responseElements to reduce output size")
    parser.add_argument("--print-sample", type=int, default=3, help="Print first N normalized events to stdout")
    args = parser.parse_args()

    mask_keys = not args.no_mask_keys

    all_events: List[Dict[str, Any]] = []
    errors: List[str] = []

    top_sources = Counter()
    top_names = Counter()
    top_actors = Counter()

    files = list(iter_input_files(args.input))
    if not files:
        print(f"No .json or .json.gz files found at: {args.input}")
        raise SystemExit(1)

    for fp in files:
        events, err = parse_cloudtrail_file(
            fp,
            mask_keys=mask_keys,
            drop_heavy_fields=args.drop_heavy_fields
        )
        if err:
            errors.append(err)
            continue

        for ev in events:
            all_events.append(ev)
            if ev.get("eventSource"):
                top_sources[str(ev["eventSource"])] += 1
            if ev.get("eventName"):
                top_names[str(ev["eventName"])] += 1
            if ev.get("actor"):
                top_actors[str(ev["actor"])] += 1

    # Write output JSONL
    total = write_jsonl(all_events, args.out)

    # Print sample
    sample_n = max(0, args.print_sample)
    if sample_n > 0:
        print("\n--- Sample normalized events ---")
        for ev in all_events[:sample_n]:
            print(json.dumps(ev, indent=2))

    print_summary(total, errors, top_sources, top_names, top_actors)
    print(f"\nWrote JSONL: {args.out}")


if __name__ == "__main__":
    main()
