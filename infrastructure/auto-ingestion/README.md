# Auto-Ingestion

Lambda function that automatically ingests CloudTrail logs into DynamoDB.
Triggered by S3 whenever CloudTrail delivers a new log file — typically
every 5–15 minutes.

---

## How it works

```
CloudTrail delivers .json.gz log file
              │
              ▼
       S3 Bucket (anomai-cloudtrail-logs-dev)
              │
              │  S3 ObjectCreated trigger
              ▼
    Lambda: anomai-ingest-cloudtrail
              │
              ├── Decompresses the .json.gz file
              ├── Normalizes each CloudTrail record
              ├── Masks access key IDs
              ├── Filters out its own activity (prevents feedback loops)
              ├── Adds day_bucket field (YYYY-MM-DD) for efficient scanning
              └── Batch-writes to DynamoDB (anomai_events)
```

---

## Files

| File | Description |
|---|---|
| `lambda/ingest/handler.py` | Lambda entry point — reads from S3, writes to DynamoDB |
| `lambda/ingest/normalize.py` | Extracts and normalizes fields from raw CloudTrail records |
| `lambda/ingest/s3-notification.json` | S3 bucket notification config — wires S3 trigger to Lambda |
| `policy-anomai-ingest.json` | IAM inline policy — S3 read + DynamoDB write |
| `trust-lambda.json` | IAM trust policy — allows Lambda service to assume the role |

---

## DynamoDB fields written per event

| Field | Source | Description |
|---|---|---|
| `event_id` | CloudTrail `eventID` (PK) | Unique identifier for the event |
| `actor` | Resolved from `userIdentity` | IAM user or role session name |
| `eventTime` | CloudTrail `eventTime` | ISO-8601 timestamp |
| `day_bucket` | Derived from `eventTime` | `YYYY-MM-DD` — used by the detection pipeline for efficient time-range scans |
| `eventName` | CloudTrail `eventName` | AWS API call (e.g. `CreateUser`) |
| `eventSource` | CloudTrail `eventSource` | AWS service (e.g. `iam.amazonaws.com`) |
| `awsRegion` | CloudTrail `awsRegion` | Region where the call was made |
| `sourceIPAddress` | CloudTrail `sourceIPAddress` | Source IP of the caller |
| `event_json` | Full normalized record | Complete event stored as a JSON string |

Access key IDs are masked (`****************XXXX`) before being stored.

---

## Deploy

This component is deployed via AWS CLI. Run each command from inside
`infrastructure/auto-ingestion/`.

### Step 1 — Create the IAM role

```bash
aws iam create-role \
  --role-name anomai-ingest-lambda-role \
  --assume-role-policy-document file://trust-lambda.json
```

Attach the AWS-managed CloudWatch logging policy:

```bash
aws iam attach-role-policy \
  --role-name anomai-ingest-lambda-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

Attach the inline policy for S3 read and DynamoDB write:

```bash
aws iam put-role-policy \
  --role-name anomai-ingest-lambda-role \
  --policy-name anomai-ingest-s3-ddb \
  --policy-document file://policy-anomai-ingest.json
```

Get the role ARN for the next step:

```bash
aws iam get-role \
  --role-name anomai-ingest-lambda-role \
  --query 'Role.Arn' \
  --output text
```

### Step 2 — Deploy the Lambda function

Zip the handler and normalizer together:

```bash
cd lambda/ingest/
zip -r function.zip handler.py normalize.py
```

Create the function (replace `<ROLE_ARN>` with the ARN from Step 1):

```bash
export FUNCTION_NAME=anomai-ingest-cloudtrail
export ROLE_ARN=<ROLE_ARN>
export AWS_REGION=us-east-2

aws lambda create-function \
  --function-name "$FUNCTION_NAME" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler handler.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 60 \
  --memory-size 256 \
  --environment "Variables={EVENTS_TABLE=anomai_events,INPUT_PREFIX=AWSLogs/,MASK_KEYS=true,KEEP_HEAVY_FIELDS=false}"
```

Verify it deployed:

```bash
aws lambda get-function \
  --function-name "$FUNCTION_NAME" \
  --query 'Configuration.State' \
  --output text
# Expected: Active
```

### Step 3 — Wire the S3 trigger

Allow S3 to invoke the Lambda:

```bash
export BUCKET=anomai-cloudtrail-logs-dev
export ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

export FUNCTION_ARN=$(aws lambda get-function \
  --function-name "$FUNCTION_NAME" \
  --query 'Configuration.FunctionArn' \
  --output text)

aws lambda add-permission \
  --function-name "$FUNCTION_NAME" \
  --statement-id s3-invoke-anomai-ingest \
  --action lambda:InvokeFunction \
  --principal s3.amazonaws.com \
  --source-arn "arn:aws:s3:::$BUCKET" \
  --source-account "$ACCOUNT_ID"
```

Apply the S3 bucket notification (update `s3-notification.json` with your
Lambda ARN first):

```bash
aws s3api put-bucket-notification-configuration \
  --bucket "$BUCKET" \
  --notification-configuration file://s3-notification.json
```

Verify:

```bash
aws s3api get-bucket-notification-configuration --bucket "$BUCKET"
```

### Step 4 — Verify end-to-end

Wait 5–10 minutes for CloudTrail to deliver a new log file, then check
that events are appearing in DynamoDB:

```bash
aws dynamodb scan --table-name anomai_events --max-items 5
```

---

## Updating the Lambda code

After making changes to `handler.py` or `normalize.py`:

```bash
cd lambda/ingest/
zip -r function.zip handler.py normalize.py

aws lambda update-function-code \
  --function-name anomai-ingest-cloudtrail \
  --zip-file fileb://function.zip
```

---

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `EVENTS_TABLE` | `anomai_events` | DynamoDB table to write events to |
| `INPUT_PREFIX` | `AWSLogs/` | Only process S3 keys under this prefix |
| `MASK_KEYS` | `true` | Mask access key IDs before storing |
| `KEEP_HEAVY_FIELDS` | `false` | Drop `requestParameters` and `responseElements` to save space |
| `SELF_ROLE_NAME` | `anomai-ingest-lambda-role` | Role name to filter out of ingestion (prevents feedback loops) |
| `SELF_SESSION_NAME` | `anomai-ingest-cloudtrail` | Session name to filter out of ingestion |

---

## IAM permissions

| Permission | Resource | Purpose |
|---|---|---|
| `s3:GetObject` | `anomai-cloudtrail-logs-dev/AWSLogs/*` | Read CloudTrail log files |
| `dynamodb:PutItem`, `BatchWriteItem`, `DescribeTable` | `anomai_events` | Write normalized events |
| `logs:CreateLogGroup/Stream/Events` | CloudWatch | Lambda execution logs |