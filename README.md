# AnomAI

**AWS IAM anomaly detection — from raw CloudTrail logs to a live security dashboard with an AI assistant.**

AnomAI monitors every API call made in an AWS account, automatically detects
suspicious behavioral IAM patterns, and surfaces incidents through a REST API and
an interactive dashboard. The entire pipeline runs on AWS with no manual
intervention required after deployment.

---

## What it detects

| Incident Type | Signal | Example |
|---|---|---|
| **Access Denied Spike** | Burst of denied API calls from one actor | Tool probing for accessible resources |
| **Sensitive IAM Spike** | Rapid permission changes in a short window | Privilege escalation attempt |
| **API Burst** | Unusually high call volume from one actor | Account enumeration before an attack |
| **New Region Activity** | AWS activity in a region never used before | Attacker hiding activity in an unmonitored region |
| **Sign-in Failure Spike** | Repeated failed logins in a short window | Brute-force or credential stuffing |
| **Invalid AMI Spike** | Repeated failed EC2 launch attempts | Broken automation or resource probing |

All thresholds are **auto-computed** from the data — no manual tuning needed.
Each detector uses `threshold = max(hard_min, median + 3 × IQR)` over a sliding
10-minute window, so the system self-calibrates to the environment it monitors.

---

## Architecture

```
AWS API activity
      │
      ▼
CloudTrail ──► S3 Bucket
                   │
                   │  S3 trigger (on every new log file)
                   ▼
            Lambda: ingest          Parses + normalizes CloudTrail records
                   │
                   ▼
            DynamoDB: anomai_events
                   │
                   │  EventBridge Scheduler (every 5 minutes)
                   ▼
            Lambda: detection       Runs all detectors, writes incidents
                   │
                   ▼
            DynamoDB: anomai_incidents_api
                   │
                   ▼
            Flask API  ──►  Streamlit Dashboard + AI Chatbot
```

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full component breakdown,
DynamoDB schema, detection logic, and infrastructure diagram.

---

## Project structure

```
AnomAI/
├── infrastructure/
│   ├── cloudtrail-s3-dynamodb/   Terraform: CloudTrail, S3, DynamoDB tables
│   ├── auto-ingestion/           Lambda: S3 trigger → parse → DynamoDB write
│   ├── detection-pipeline/       Lambda + EventBridge: detection every 5 min
│   └── demo-actors/              IAM roles for demo and testing
│
├── scripts/
│   ├── pipeline/                 Unified detection pipeline + Flask API
│   ├── activity_generator/       Generates test CloudTrail activity
│   ├── parse/                    CloudTrail .gz file parser (early dev tool)
│   ├── backfill_day/             Utility: fix missing day_bucket fields
│   ├── data_export/              Utility: export events from DynamoDB
│   ├── s3/                       S3 utility scripts
│   └── detection_v1/             Original two-script pipeline (archived)
│
├── ui/                           Streamlit dashboard + AI chatbot
├── research/                     Design docs, API schema, detection research
├── docs/                         Team docs, AWS SSO guide
│
├── ARCHITECTURE.md               Full system architecture
├── .env.example                  Environment variable template
└── .gitignore
```

---

## Quick start

### Prerequisites

- AWS account with SSO configured
- GitHub Codespace (recommended) or local environment with AWS CLI + Terraform
- Python 3.11+

### 1. Base infrastructure

Provisions CloudTrail, the S3 bucket, and DynamoDB tables:

```bash
cd infrastructure/cloudtrail-s3-dynamodb/
cp terraform.tfvars.example terraform.tfvars
terraform init && terraform apply
```

### 2. Ingest Lambda

Deploys the Lambda that fires automatically on every new CloudTrail log file:

```bash
cd infrastructure/auto-ingestion/
# Follow the README for AWS CLI deployment steps
```

### 3. Detection pipeline Lambda

Runs the full detection pipeline every 5 minutes via EventBridge:

```bash
cd infrastructure/detection-pipeline/
zip terraform/lambda.zip lambda_handler.py
cd terraform/
terraform init && terraform apply
```

### 4. Flask API

```bash
cd scripts/pipeline/
pip install -r requirements-api.txt
python anomai_incidents_api.py
# Running at http://localhost:8000
```

### 5. Streamlit dashboard

```bash
cd ui/
pip install -r requirements.txt
cp ../.env.example .env      # add your Gemini API key
streamlit run app.py
```

---

## Running the pipeline manually

Useful for testing or backfilling without waiting for the Lambda schedule:

```bash
cd scripts/pipeline/

# Basic run
python anomai_pipeline.py

# Custom lookback
python anomai_pipeline.py --region us-east-2 --lookback-days 90

# Dry run — detects but does not write to DynamoDB
python anomai_pipeline.py --dry-run

# Verbose debug output
python anomai_pipeline.py --debug
```

---

## Generating test activity

Three IAM demo roles are provided for generating realistic CloudTrail activity
to test and demonstrate the detectors:

```bash
# Deploy demo roles
cd infrastructure/demo-actors/terraform/
cp terraform.tfvars.example terraform.tfvars    # add your account ID
terraform init && terraform apply

# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::<account-id>:role/anomai-demo-alice \
  --role-session-name alice-session

export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Run a scenario
bash scripts/activity_generator/generate_activity.sh \
  --scenario access_denied_spike --duration 120 --rate 90
```

Wait ~5 minutes for the detection Lambda to pick it up, then check the dashboard.

---

## Environment variables

| Variable | Used by | Default | Description |
|---|---|---|---|
| `AWS_REGION` | All | `us-east-2` | AWS region |
| `ANOMAI_SOURCE_TABLE` | Lambda | `anomai_events` | Source events table |
| `ANOMAI_DEST_TABLE` | Lambda | `anomai_incidents_api` | Incidents output table |
| `ANOMAI_LOOKBACK_DAYS` | Lambda | `120` | Days of events to scan per run |
| `ANOMAI_INCIDENTS_TABLE` | Flask API | `anomai_incidents_api` | Table the API reads from |
| `ANOMAI_API_URL` | Streamlit | `http://localhost:8000` | Flask API base URL |
| `GOOGLE_API_KEY` | Streamlit | — | Gemini API key for the AI chatbot |

Copy `.env.example` to `.env` and fill in your values. Never commit `.env`.

---

## Tech stack

| | |
|---|---|
| **Cloud** | AWS (CloudTrail, S3, Lambda, DynamoDB, EventBridge, IAM) |
| **IaC** | Terraform |
| **Backend** | Python 3.12, Flask, boto3 |
| **Detection** | Custom spike detection (sliding windows, auto-threshold) |
| **Dashboard** | Streamlit, Plotly |
| **AI assistant** | Google Gemini (`gemini-3-flash-preview`) |
| **Dev environment** | GitHub Codespaces |

---

## Anomaly Detection Research

This project includes a full breakdown of the IAM anomaly detection research,
covering behavior analysis, feature engineering, scoring logic, embedding
design, and the final incident schema.

See [AnomalyResearch.md](./AnomalyResearch.md) for the complete Week 1–11
research notes.

### Research Structure

### Research Flow

```
### Research Flow (Architecture Style)

```
┌──────────────────────────────┐
│ Week 1: Behavior Foundations  │
└───────────────┬──────────────┘
                ▼
┌────────────────────────────────────────┐
│ Week 2: Normalization Pipeline         │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 3: Rule-Based Features            │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 4: Embedding & Model Research     │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 5: Final Scoring Logic            │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 6: API Specification              │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 7: Validation & Documentation     │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 8: UI Alignment                   │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 9: Error Handling & Robustness    │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 10: Documentation Freeze          │
└────────────────┬───────────────────────┘
                 ▼
┌────────────────────────────────────────┐
│ Week 11: UI Integration & Final Polish │
└────────────────────────────────────────┘
```
