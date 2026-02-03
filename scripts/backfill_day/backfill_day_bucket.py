import os
import time
from datetime import datetime
import boto3
from botocore.exceptions import ClientError

TABLE_NAME = os.getenv("EVENTS_TABLE", "anomai_events")
REGION = os.getenv("AWS_REGION", "us-east-2")

# Safety knobs
PAGE_LIMIT = int(os.getenv("PAGE_LIMIT", "250"))      # scan page size
MAX_UPDATES = int(os.getenv("MAX_UPDATES", "0"))      # 0 = no limit
SLEEP_MS = int(os.getenv("SLEEP_MS", "10"))           # tiny throttle

ddb = boto3.client("dynamodb", region_name=REGION)

def to_day_bucket(event_time: str) -> str:
    # eventTime looks like: 2026-02-03T14:18:48Z
    # We only need YYYY-MM-DD
    return event_time[:10]

updated = 0
scanned = 0
last_key = None

while True:
    kwargs = {
        "TableName": TABLE_NAME,
        "Limit": PAGE_LIMIT,
        "ProjectionExpression": "event_id,eventTime,day_bucket",
    }
    if last_key:
        kwargs["ExclusiveStartKey"] = last_key

    resp = ddb.scan(**kwargs)
    items = resp.get("Items", [])
    scanned += len(items)

    for it in items:
        # only update missing day_bucket
        has_bucket = ("day_bucket" in it and it["day_bucket"].get("S"))
        if has_bucket:
            continue

        event_id = it["event_id"]["S"]
        event_time = it.get("eventTime", {}).get("S", "")
        if not event_time:
            continue

        day_bucket = to_day_bucket(event_time)

        try:
            ddb.update_item(
                TableName=TABLE_NAME,
                Key={"event_id": {"S": event_id}},
                UpdateExpression="SET day_bucket = :d",
                ExpressionAttributeValues={":d": {"S": day_bucket}},
                ConditionExpression="attribute_not_exists(day_bucket)",
            )
            updated += 1
        except ClientError as e:
            # if someone else already wrote it, ignore
            if e.response["Error"]["Code"] != "ConditionalCheckFailedException":
                raise

        if MAX_UPDATES and updated >= MAX_UPDATES:
            print(f"[STOP] reached MAX_UPDATES={MAX_UPDATES}")
            print(f"[OK] scanned={scanned} updated={updated}")
            raise SystemExit(0)

        if SLEEP_MS > 0:
            time.sleep(SLEEP_MS / 1000.0)

    last_key = resp.get("LastEvaluatedKey")
    if not last_key:
        break

print(f"[OK] scanned={scanned} updated={updated}")