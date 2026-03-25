# AnomAI — System Architecture

## Overview

AnomAI is an AWS-native IAM anomaly detection system. It continuously monitors
CloudTrail API logs, detects suspicious IAM behavioral patterns using statistical
spike detection, and surfaces incidents through a REST API and a Streamlit
dashboard with an AI security assistant.

The system is fully automated — once deployed, it requires no manual runs.
Every component is event-driven or scheduled.

---

## Full Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AWS ACCOUNT                                  │
│                                                                      │
│  Every API call made in the account                                  │
│          │                                                           │
│          ▼                                                           │
│  ┌───────────────┐                                                   │
│  │  CloudTrail   │  Captures all AWS API activity (multi-region)     │
│  └───────┬───────┘                                                   │
│          │ delivers .json.gz logs                                    │
│          ▼                                                           │
│  ┌───────────────────────┐                                           │
│  │  S3 Bucket            │  anomai-cloudtrail-logs-dev               │
│  │  (AWSLogs/...)        │                                           │
│  └───────────┬───────────┘                                           │
│              │ S3 ObjectCreated trigger                              │
│              ▼                                                       │
│  ┌───────────────────────┐                                           │
│  │  Lambda: ingest       │  Parses + normalizes CloudTrail records   │
│  │  (handler.py)         │  Filters out its own activity             │
│  │                       │  Writes normalized events to DynamoDB     │
│  └───────────┬───────────┘                                           │
│              │ batch write                                           │
│              ▼                                                       │
│  ┌───────────────────────┐                                           │
│  │  DynamoDB             │  anomai_events                            │
│  │  (events table)       │  PK: event_id                             │
│  │                       │  GSI filter: day_bucket (YYYY-MM-DD)      │
│  └───────────┬───────────┘                                           │
│              │                                                       │
│              │  EventBridge fires every 5 minutes                   │
│              ▼                                                       │
│  ┌───────────────────────┐                                           │
│  │  Lambda: detection    │  Scans last 120 days of events            │
│  │  (lambda_handler.py)  │  Runs all detectors (spike clustering)    │
│  │                       │  Converts to API schema                   │
│  │                       │  Writes new incidents (skip-if-exists)    │
│  └───────────┬───────────┘                                           │
│              │ conditional put_item                                  │
│              ▼                                                       │
│  ┌───────────────────────┐                                           │
│  │  DynamoDB             │  anomai_incidents_api                     │
│  │  (incidents table)    │  PK: incident_id (inc_YYYYMMDD_xxxxxx)    │
│  └───────────┬───────────┘                                           │
│              │                                                       │
└──────────────┼──────────────────────────────────────────────────────┘
               │
               ▼
   ┌───────────────────────┐
   │  Flask API            │  Reads from anomai_incidents_api
   │  (anomai_incidents    │  Serves /incidents and /incidents/<id>
   │   _api.py)            │  Runs locally or on App Runner
   └───────────┬───────────┘
               │ HTTP GET /incidents
               ▼
   ┌───────────────────────┐
   │  Streamlit Dashboard  │  Filters, charts, incident detail panel
   │  (ui/app.py)          │  AI chatbot powered by Gemini
   └───────────────────────┘
```

---

## Components

### 1. CloudTrail + S3 (`infrastructure/cloudtrail-s3-dynamodb/`)

Provisioned with Terraform.

- **CloudTrail** `anomai-dev` — multi-region trail, captures all AWS API calls
  including IAM, STS, EC2, and management events
- **S3 bucket** `anomai-cloudtrail-logs-dev` — receives compressed `.json.gz`
  log files under `AWSLogs/<account-id>/`

---

### 2. Ingest Lambda (`infrastructure/auto-ingestion/`)

Triggered by S3 `ObjectCreated` events. Fires automatically whenever CloudTrail
delivers a new log file (typically every 5–15 minutes).

**What it does:**
- Decompresses the `.json.gz` CloudTrail file
- Normalizes each record (extracts actor, region, event name, error codes)
- Masks access key IDs for security
- Filters out its own activity to prevent feedback loops
- Batch-writes normalized events to `anomai_events` DynamoDB table

**Key fields written per event:**

| Field | Description |
|---|---|
| `event_id` | CloudTrail `eventID` (partition key) |
| `actor` | Resolved IAM user or role session name |
| `day_bucket` | `YYYY-MM-DD` — used for efficient time-range scans |
| `eventName` | AWS API call name (e.g. `CreateUser`) |
| `eventSource` | AWS service (e.g. `iam.amazonaws.com`) |
| `awsRegion` | Region where the call was made |
| `event_json` | Full normalized event as JSON string |

---

### 3. Detection Lambda (`infrastructure/detection-pipeline/`)

Triggered by **EventBridge Scheduler every 5 minutes**.

**What it does:**
1. Scans `anomai_events` for the last 120 days (filtered by `day_bucket`)
2. Normalizes events into typed Event objects
3. Runs six detectors in parallel (see Detection Logic below)
4. Deduplicates incidents by stable deterministic ID
5. Converts each incident to the API schema
6. Writes only new incidents to `anomai_incidents_api` using
   `ConditionExpression: attribute_not_exists(incident_id)` — guarantees
   no duplicates even if Lambda fires twice

---

### 4. Detection Logic (`scripts/pipeline/anomai_pipeline.py`)

The same detection logic runs both locally (for development/testing) and inside
the Lambda. Six detectors are implemented:

| Detector | Incident Type | How it works |
|---|---|---|
| Access Denied Spike | `AccessDeniedSpike` | Sliding 10-minute window; fires when denied call count exceeds auto-computed baseline (median + 3×IQR) |
| Sensitive IAM Spike | `SensitiveIAMSpike` | Same windowing logic; matches against a list of 14 high-risk IAM actions |
| API Burst | `APIBurst` | Per-actor call count in sliding windows; fires when any actor peaks above threshold |
| New Region Activity | `NewRegion` | Compares regions used in first 7 days vs. later; flags new regions |
| Sign-in Failure Spike | `SigninFailureSpike` | Matches ConsoleLogin failures and auth errors in sliding windows |
| Invalid AMI Spike | `InvalidAMISpike` | Matches `RunInstances` calls with `InvalidAMIId.Malformed` error |

**Threshold computation:** No manual thresholds are set. Each detector computes
its own threshold from the data distribution: `threshold = max(hard_min, median + 3 × IQR)`.
This means the system self-calibrates to the environment it's monitoring.

**Incident ID stability:** Each incident gets a deterministic ID based on
`type + first_seen + last_seen + severity`. The same incident always gets the
same ID across reruns, which is what makes skip-if-exists dedup work correctly.

---

### 5. Flask API (`scripts/pipeline/anomai_incidents_api.py`)

A lightweight Flask app that reads from `anomai_incidents_api` and serves:

| Endpoint | Description |
|---|---|
| `GET /incidents` | All incidents, sorted newest first. Supports `?severity=high` and `?is_new=true` filters |
| `GET /incidents/<id>` | Single incident by ID (uses `get_item` — no scan) |
| `GET /health` | Liveness check including DynamoDB connectivity |

---

### 6. Streamlit Dashboard (`ui/app.py`)

Single-page app with two views:

**Dashboard** — Metrics (total incidents, last 2 weeks, high severity, top actor),
three charts (severity breakdown, incident types, incidents by month), incidents
table with severity colour coding, incident detail panel.

**AI Chatbot** — Powered by Google Gemini. The model is grounded with live
incident data from the API on every session start. Trained via system prompt to
act as an IAM anomaly specialist — explains incidents in plain English, gives
step-by-step remediation guidance, refuses to answer anything outside the
incident data.

---

## Infrastructure Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Terraform Managed                     │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  infrastructure/cloudtrail-s3-dynamodb/          │   │
│  │  • aws_cloudtrail.trail (anomai-dev)             │   │
│  │  • aws_s3_bucket.logs                            │   │
│  │  • aws_dynamodb_table.events (anomai_events)     │   │
│  │  • aws_dynamodb_table.incidents                  │   │
│  │  • aws_dynamodb_table.baselines                  │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  infrastructure/detection-pipeline/terraform/    │   │
│  │  • aws_lambda_function.anomai_pipeline           │   │
│  │  • aws_scheduler_schedule (rate 5 min)           │   │
│  │  • aws_iam_role (least-privilege DynamoDB)       │   │
│  │  • aws_cloudwatch_log_group (14-day retention)   │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │  infrastructure/demo-actors/terraform/           │   │
│  │  • aws_iam_role: anomai-demo-alice               │   │
│  │  • aws_iam_role: anomai-demo-arthur              │   │
│  │  • aws_iam_role: anomai-demo-john                │   │
│  └──────────────────────────────────────────────────┘   │
│                                                          │
│  infrastructure/auto-ingestion/  (deployed via AWS CLI)  │
│  • Lambda: anomai-ingest-cloudtrail                      │
│  • IAM role: anomai-ingest-lambda-role                   │
│  • S3 bucket notification trigger                        │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## DynamoDB Tables

| Table | Partition Key | Purpose |
|---|---|---|
| `anomai_events` | `event_id` (S) | Raw normalized CloudTrail events |
| `anomai_incidents_api` | `incident_id` (S) | Processed API-ready incidents |
| `anomai_baselines` | `baseline_id` (S) | Reserved for future baseline storage |
| `anomai_incidents` | `incident_id` (S) | Legacy table from initial Terraform setup |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Cloud provider | AWS |
| Infrastructure as Code | Terraform |
| Log ingestion | AWS Lambda (Python 3.11), S3, CloudTrail |
| Detection pipeline | AWS Lambda (Python 3.12), EventBridge Scheduler |
| Data store | Amazon DynamoDB |
| API | Python / Flask |
| Dashboard | Python / Streamlit, Plotly |
| AI assistant | Google Gemini (`gemini-2.0-flash`) |
| Development environment | GitHub Codespaces |
| Secrets management | Environment variables / `.env` (never committed) |