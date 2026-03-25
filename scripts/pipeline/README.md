# Pipeline

The unified detection pipeline and Flask API. Together these two scripts
form the core of AnomAI — detecting anomalies from CloudTrail events and
serving them over HTTP.

---

## Files

| File | Description |
|---|---|
| `anomai_pipeline.py` | Detection pipeline — scans DynamoDB, runs all detectors, writes incidents |
| `anomai_incidents_api.py` | Flask API — serves incidents from DynamoDB over HTTP |
| `requirements.txt` | Dependencies for the pipeline script |
| `requirements-api.txt` | Dependencies for the Flask API |

---

## anomai_pipeline.py

Reads normalized CloudTrail events from `anomai_events`, runs six spike
detectors, converts incidents to the API schema, and writes new ones to
`anomai_incidents_api`. This is the same logic that runs inside the
detection Lambda — the script is useful for local development, testing,
and manual backfills.

### Install

```bash
pip install -r requirements.txt
```

### Run

```bash
# Basic run — uses all defaults
python anomai_pipeline.py

# Explicit region and tables
python anomai_pipeline.py \
  --region us-east-2 \
  --table anomai_events \
  --dest-table anomai_incidents_api

# Shorter lookback for faster local testing
python anomai_pipeline.py --lookback-days 14

# Dry run — detects incidents but does not write anything to DynamoDB
python anomai_pipeline.py --dry-run

# Debug output — prints scan pages, detector thresholds, and write details
python anomai_pipeline.py --debug
```

### CLI flags

| Flag | Default | Description |
|---|---|---|
| `--region` | `us-east-2` | AWS region (also reads `AWS_REGION` env var) |
| `--table` | `anomai_events` | Source DynamoDB table |
| `--dest-table` | `anomai_incidents_api` | Destination DynamoDB table |
| `--lookback-days` | `120` | Days of events to scan |
| `--max-items` | unlimited | Cap on events returned (useful for quick tests) |
| `--debug` | off | Verbose logging |

### What it prints

```
=== AnomAI Pipeline Summary ===
events_scanned:     7192
time_range:         2025-11-25T00:00:00Z .. 2026-03-25T18:50:52Z
detected_incidents: 11 (new: 0)
written_to_table:   0 -> anomai_incidents_api

Top API incidents (newest first):
     [MEDIUM] inc_20260307_cc38c7  Sign-in/auth failures spike: 7 events
  ...
```

`new: 0` on a re-run is correct — it means all incidents already exist in
the destination table and duplicates were correctly skipped.

---

## anomai_incidents_api.py

Flask API that reads from `anomai_incidents_api` and serves incident data
over HTTP. Used by the Streamlit dashboard.

### Install

```bash
pip install -r requirements-api.txt
```

### Run

```bash
python anomai_incidents_api.py
# Running at http://localhost:8000
```

### Endpoints

#### `GET /health`

Liveness check. Also verifies DynamoDB connectivity.

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "ok",
  "dynamodb": "ok",
  "table": "anomai_incidents_api",
  "region": "us-east-2",
  "service": "anomai-api",
  "timestamp": "2026-03-25T18:00:00+00:00"
}
```

Returns `503` with `"status": "degraded"` if DynamoDB is unreachable.

#### `GET /incidents`

Returns all incidents sorted newest first.

```bash
curl http://localhost:8000/incidents
```

**Optional query parameters:**

| Parameter | Example | Description |
|---|---|---|
| `?severity=high` | `?severity=high` | Filter by severity (`high`, `medium`, `low`) |
| `?is_new=true` | `?is_new=true` | Return only new incidents |
| `?pretty=1` | `?pretty=1` | Pretty-print the JSON response |

```bash
# Only high severity incidents, formatted
curl "http://localhost:8000/incidents?severity=high&pretty=1"
```

#### `GET /incidents/<incident_id>`

Fetch a single incident by ID. Uses `get_item` — does not scan the whole table.

```bash
curl http://localhost:8000/incidents/inc_20260203_d19685
```

Returns `404` if the incident ID does not exist.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `AWS_REGION` | `us-east-2` | AWS region |
| `ANOMAI_INCIDENTS_TABLE` | `anomai_incidents_api` | DynamoDB table to read from |

---

## Relationship between the two scripts

```
anomai_pipeline.py          anomai_incidents_api.py
        │                             │
        │  writes incidents           │  reads incidents
        ▼                             ▼
   DynamoDB: anomai_incidents_api ◄──►
```

The pipeline and API are fully decoupled — the pipeline can run on any
schedule (or manually) and the API always reflects whatever is currently
in the table. In production, the pipeline runs as a Lambda every 5 minutes.
The API runs as a local Flask server or on AWS App Runner.