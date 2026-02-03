import boto3
import os

TABLE_NAME = os.getenv("EVENTS_TABLE", "anomai_events")
REGION = os.getenv("AWS_REGION", "us-east-2")

ddb = boto3.client("dynamodb", region_name=REGION)

missing = 0
total = 0
last_key = None

while True:
    kwargs = {"TableName": TABLE_NAME}
    if last_key:
        kwargs["ExclusiveStartKey"] = last_key

    resp = ddb.scan(**kwargs)

    for item in resp.get("Items", []):
        total += 1
        if "day_bucket" not in item or not item["day_bucket"].get("S"):
            missing += 1

    last_key = resp.get("LastEvaluatedKey")
    if not last_key:
        break

print(f"[RESULT] total_items={total} missing_day_bucket={missing}")
