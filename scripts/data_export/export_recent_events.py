import json
import boto3
from decimal import Decimal

TABLE_NAME = "anomai_events"
OUTPUT_FILE = "sample_events.json"
REGION_NAME = "us-east-2"
MAX_EVENTS = 100

#convert DynamoDB decimal to float/int for JSON
def convert_decimal(obj):
    if isinstance(obj, list):
        return [convert_decimal(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return float(obj)
    else:
        return obj

def fetch_recent_events(max_events = MAX_EVENTS):
    #connect to DynamoDB
    dynamodb = boto3.resource("dynamodb", region_name = REGION_NAME)
    table = dynamodb.Table(TABLE_NAME)

    #scan table
    response = table.scan()
    items = response.get("Items", [])

    #sort by time
    sorted_items = sorted(items, key=lambda x: x.get("eventTime", ""), reverse=True)

    #keep 50
    return sorted_items[:max_events]

def save_to_json(events, filename = OUTPUT_FILE):
    cleaned = convert_decimal(events)
    with open(filename, "w") as f:
        #save to JSON
        json.dump(cleaned, f, indent=2)
    print(f"[+] Saved {len(cleaned)} events to {filename}")

if __name__ == "__main__":
    events = fetch_recent_events(MAX_EVENTS)
    save_to_json(events, OUTPUT_FILE)
