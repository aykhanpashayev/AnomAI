# handler.py
import gzip
import json
import os
from typing import Any, Dict, List

import boto3

from normalize import normalize_record

s3 = boto3.client("s3")
ddb = boto3.client("dynamodb")

TABLE_NAME = os.getenv("EVENTS_TABLE", "anomai_events")
INPUT_PREFIX = os.getenv("INPUT_PREFIX", "AWSLogs/")
MASK_KEYS = os.getenv("MASK_KEYS", "true").lower() == "true"
KEEP_HEAVY_FIELDS = os.getenv("KEEP_HEAVY_FIELDS", "false").lower() == "true"

# Self-filter settings (prevents ingestion Lambda from ingesting its own CloudTrail noise)
SELF_ROLE_NAME = os.getenv("SELF_ROLE_NAME", "anomai-ingest-lambda-role")
SELF_SESSION_NAME = os.getenv("SELF_SESSION_NAME", "anomai-ingest-cloudtrail")


def _is_self_event(ev: Dict[str, Any]) -> bool:
    role_name = (ev.get("roleName") or "").strip()
    session_name = (ev.get("sessionName") or "").strip()
    user_arn = (ev.get("userArn") or "").strip()

    if role_name == SELF_ROLE_NAME:
        return True
    if session_name == SELF_SESSION_NAME:
        return True
    if f":assumed-role/{SELF_ROLE_NAME}/" in user_arn:
        return True
    return False


def _safe_str(v) -> str:
    return "" if v is None else str(v)


def _make_item(ev: Dict[str, Any], source_bucket: str, source_key: str) -> Dict[str, Any]:
    """
    Convert a normalized CloudTrail event into a DynamoDB item.

    Adds a derived attribute: day_bucket = "YYYY-MM-DD"
    This is used later for efficient time-based queries via a GSI.
    """
    # DynamoDB PK must be present. Use CloudTrail eventID if available.
    event_id = _safe_str(ev.get("eventID"))
    if not event_id:
        event_id = f"NOEVENTID#{_safe_str(ev.get('eventTime'))}#{_safe_str(ev.get('requestID'))}"

    ev_time = _safe_str(ev.get("eventTime"))  # e.g. "2026-02-02T19:59:56Z"
    day_bucket = ev_time[:10] if len(ev_time) >= 10 else ""  # e.g. "2026-02-02"

    ev_json = json.dumps(ev, ensure_ascii=False)

    return {
        "event_id": {"S": event_id},
        "actor": {"S": _safe_str(ev.get("actor"))},
        "eventTime": {"S": ev_time},
        "day_bucket": {"S": day_bucket},  # ✅ NEW FIELD
        "eventName": {"S": _safe_str(ev.get("eventName"))},
        "eventSource": {"S": _safe_str(ev.get("eventSource"))},
        "awsRegion": {"S": _safe_str(ev.get("awsRegion"))},
        "accountId": {"S": _safe_str(ev.get("accountId"))},
        "sourceIPAddress": {"S": _safe_str(ev.get("sourceIPAddress"))},
        "s3_bucket": {"S": source_bucket},
        "s3_key": {"S": source_key},
        "event_json": {"S": ev_json},
    }


def _batch_write(items: List[Dict[str, Any]]) -> int:
    written = 0

    for i in range(0, len(items), 25):
        chunk = items[i : i + 25]
        req = {TABLE_NAME: [{"PutRequest": {"Item": it}} for it in chunk]}

        resp = ddb.batch_write_item(RequestItems=req)

        # Retry unprocessed items up to 5 times
        unprocessed = resp.get("UnprocessedItems", {})
        tries = 0
        while unprocessed and tries < 5:
            tries += 1
            resp = ddb.batch_write_item(RequestItems=unprocessed)
            unprocessed = resp.get("UnprocessedItems", {})

        if unprocessed:
            unproc_count = sum(len(v) for v in unprocessed.values())
            written += len(chunk) - unproc_count
        else:
            written += len(chunk)

    return written


def lambda_handler(event, context):
    records = event.get("Records", [])
    total_events = 0
    total_written = 0

    for rec in records:
        bucket = rec.get("s3", {}).get("bucket", {}).get("name")
        key = rec.get("s3", {}).get("object", {}).get("key")
        if not bucket or not key:
            continue

        # Only CloudTrail gzip logs in AWSLogs/
        if not key.startswith(INPUT_PREFIX) or not key.endswith(".json.gz"):
            continue

        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()

        data = json.loads(gzip.decompress(body).decode("utf-8"))
        ct_records = data.get("Records", [])
        if not isinstance(ct_records, list):
            continue

        normalized_events: List[Dict[str, Any]] = []
        for r in ct_records:
            if not isinstance(r, dict):
                continue

            ev = normalize_record(
                r,
                mask_keys=MASK_KEYS,
                keep_heavy_fields=KEEP_HEAVY_FIELDS,
            )

            # Skip ingestion Lambda's own CloudTrail events (prevents dataset pollution)
            if _is_self_event(ev):
                continue

            normalized_events.append(ev)

        total_events += len(normalized_events)

        items = [_make_item(ev, bucket, key) for ev in normalized_events]
        total_written += _batch_write(items)

    return {"ok": True, "eventsParsed": total_events, "itemsWritten": total_written}