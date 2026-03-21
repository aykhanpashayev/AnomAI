from flask import Flask, jsonify, request, make_response
import os
import json
from datetime import datetime, timezone

# -----------------------------------
# Create Flask app
# -----------------------------------
app = Flask(__name__)

# -----------------------------------
# Configuration
# -----------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_SCRIPT_DIR, "..", ".."))

INCIDENTS_FILE = os.environ.get(
    "ANOMAI_INCIDENTS_FILE",
    os.path.join(_PROJECT_ROOT, "out", "incidents_api.json")
)

# -----------------------------------
# Utility Functions
# -----------------------------------
def load_incidents():
    if not os.path.exists(INCIDENTS_FILE):
        return []

    with open(INCIDENTS_FILE, "r") as f:
        return json.load(f)


def json_response(payload, status=200):
    """
    Returns JSON.
    If ?pretty=1 → formatted JSON.
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
# Health Check
# -----------------------------------
@app.route("/health", methods=["GET"])
def health():
    return json_response({
        "status": "ok",
        "service": "anomai-api",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


# -----------------------------------
# GET /incidents
# Returns all incidents
# -----------------------------------
@app.route("/incidents", methods=["GET"])
def list_incidents():
    incidents = load_incidents()

    # Sort newest first
    incidents_sorted = sorted(
        incidents,
        key=lambda i: i.get("timestamp_detected", ""),
        reverse=True
    )

    response = {
        "count": len(incidents_sorted),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incidents": incidents_sorted
    }

    return json_response(response)


# -----------------------------------
# GET /incidents/<incident_id>
# -----------------------------------
@app.route("/incidents/<incident_id>", methods=["GET"])
def get_incident(incident_id):
    incidents = load_incidents()

    for incident in incidents:
        if str(incident.get("incident_id")) == incident_id:
            return json_response(incident)

    return json_response({
        "error": "Incident not found",
        "incident_id": incident_id
    }, status=404)


# -----------------------------------
# Run App
# -----------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)