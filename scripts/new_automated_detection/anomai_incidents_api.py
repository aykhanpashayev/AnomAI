from flask import Flask, jsonify, request, make_response
import os
import json
import logging
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# -----------------------------------
# Create Flask app
# -----------------------------------
app = Flask(__name__)

# -----------------------------------
# Logging
# -----------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("anomai-api")

# -----------------------------------
# Configuration (env vars with defaults)
# -----------------------------------
DYNAMO_REGION     = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-2"
INCIDENTS_TABLE   = os.environ.get("ANOMAI_INCIDENTS_TABLE", "anomai_incidents_api")

# -----------------------------------
# DynamoDB client (module-level, reused across requests)
# -----------------------------------
_ddb_resource = None

def get_table():
    """Return a boto3 DynamoDB Table resource, creating it once per process."""
    global _ddb_resource
    if _ddb_resource is None:
        session = boto3.session.Session(region_name=DYNAMO_REGION)
        _ddb_resource = session.resource("dynamodb")
    return _ddb_resource.Table(INCIDENTS_TABLE)


# -----------------------------------
# DynamoDB type helpers
# -----------------------------------
def _decode(value: Any) -> Any:
    """
    Recursively convert DynamoDB types that JSON can't handle:
      - Decimal  → int if whole number, else float
      - set      → list (DynamoDB returns SS/NS/BS as Python sets)
    """
    if isinstance(value, Decimal):
        return int(value) if value % 1 == 0 else float(value)
    if isinstance(value, dict):
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_decode(v) for v in value]
    if isinstance(value, set):
        return [_decode(v) for v in sorted(value)]
    return value


# -----------------------------------
# Data access
# -----------------------------------
def load_incidents() -> List[Dict[str, Any]]:
    """
    Scan the anomai_incidents_api DynamoDB table and return all items
    as plain Python dicts (Decimal values converted to int/float).
    Returns an empty list on any error so the API stays up.
    """
    try:
        table = get_table()
        items: List[Dict[str, Any]] = []
        last_key = None

        while True:
            kwargs: Dict[str, Any] = {}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

            resp = table.scan(**kwargs)
            items.extend(_decode(item) for item in resp.get("Items", []))

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

        log.info("Loaded %d incidents from DynamoDB table '%s'", len(items), INCIDENTS_TABLE)
        return items

    except (BotoCoreError, ClientError) as exc:
        log.error("Failed to scan DynamoDB table '%s': %s", INCIDENTS_TABLE, exc)
        return []


def get_incident_by_id(incident_id: str) -> Dict[str, Any] | None:
    """
    Fetch a single incident by partition key.
    Uses get_item (1 read) instead of scanning the whole table.
    Returns None if not found or on error.
    """
    try:
        table = get_table()
        resp = table.get_item(Key={"incident_id": incident_id})
        item = resp.get("Item")
        return _decode(item) if item else None

    except (BotoCoreError, ClientError) as exc:
        log.error("Failed to get incident '%s' from DynamoDB: %s", incident_id, exc)
        return None


# -----------------------------------
# Utility
# -----------------------------------
def json_response(payload, status=200):
    """
    Return a JSON response.
    Add ?pretty=1 to the request URL for formatted output.
    """
    pretty = request.args.get("pretty") in ("1", "true", "yes")

    if pretty:
        resp = make_response(json.dumps(payload, indent=2), status)
        resp.headers["Content-Type"] = "application/json"
        return resp

    return make_response(jsonify(payload), status)


# -----------------------------------
# Homepage
# -----------------------------------
@app.route("/")
def index():
    return """
    <h1>AnomAI Incident API</h1>
    <p>Available endpoints:</p>
    <ul>
        <li><a href="/health">/health</a></li>
        <li><a href="/incidents">/incidents</a></li>
        <li><a href="/incidents?pretty=1">/incidents?pretty=1</a></li>
    </ul>
    <p>Individual incident:</p>
    <ul>
        <li>/incidents/&lt;incident_id&gt;</li>
    </ul>
    """


# -----------------------------------
# Health check
# -----------------------------------
@app.route("/health", methods=["GET"])
def health():
    """
    Returns ok if the API is running.
    Also checks DynamoDB connectivity by describing the table.
    """
    db_status = "ok"
    try:
        get_table().load()  # lightweight describe call
    except Exception as exc:
        db_status = f"error: {exc}"
        log.error("DynamoDB health check failed: %s", exc)

    status_code = 200 if db_status == "ok" else 503
    return json_response({
        "status": "ok" if db_status == "ok" else "degraded",
        "dynamodb": db_status,
        "table": INCIDENTS_TABLE,
        "region": DYNAMO_REGION,
        "service": "anomai-api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }, status=status_code)


# -----------------------------------
# GET /incidents
# -----------------------------------
@app.route("/incidents", methods=["GET"])
def list_incidents():
    """
    Returns all incidents from DynamoDB, sorted newest first by timestamp_detected.

    Optional query params:
      ?pretty=1          — formatted JSON
      ?severity=high     — filter by severity (high / medium / low)
      ?is_new=true       — filter to only new incidents
    """
    incidents = load_incidents()

    # Optional filters
    severity_filter = (request.args.get("severity") or "").lower().strip()
    if severity_filter:
        incidents = [i for i in incidents if (i.get("severity") or "").lower() == severity_filter]

    is_new_filter = request.args.get("is_new", "").lower().strip()
    if is_new_filter in ("true", "1", "yes"):
        incidents = [i for i in incidents if i.get("is_new") is True]

    # Sort newest first
    incidents_sorted = sorted(
        incidents,
        key=lambda i: i.get("timestamp_detected") or "",
        reverse=True,
    )

    return json_response({
        "count": len(incidents_sorted),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incidents": incidents_sorted,
    })


# -----------------------------------
# GET /incidents/<incident_id>
# -----------------------------------
@app.route("/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    """
    Fetch a single incident by its incident_id.
    Uses DynamoDB get_item (single read, not a full scan).
    """
    incident = get_incident_by_id(incident_id)

    if incident is None:
        return json_response({
            "error": "Incident not found",
            "incident_id": incident_id,
        }, status=404)

    return json_response(incident)


# -----------------------------------
# Run
# -----------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)