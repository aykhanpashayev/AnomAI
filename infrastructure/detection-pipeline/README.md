# Detection Pipeline

Automated detection pipeline deployed as an AWS Lambda function, triggered
every 5 minutes by EventBridge Scheduler. Scans CloudTrail events from
DynamoDB, runs all anomaly detectors, and writes new incidents back to DynamoDB.

---

## How it works

```
EventBridge Scheduler (every 5 minutes)
            │
            ▼
    Lambda: anomai-pipeline
            │
            ├── Scans anomai_events (last 120 days, filtered by day_bucket)
            ├── Runs 6 detectors (sliding window spike detection)
            ├── Deduplicates by stable incident ID
            ├── Converts to API schema
            └── Writes new incidents to anomai_incidents_api
                (conditional put — skips if incident already exists)
```

No intermediate files. No manual runs needed once deployed.

---

## Files

| File | Description |
|---|---|
| `lambda_handler.py` | Full detection pipeline adapted for Lambda execution |
| `terraform/main.tf` | Creates all AWS resources (Lambda, IAM, EventBridge, CloudWatch) |

---

## Prerequisites

- Base infrastructure already deployed (`infrastructure/cloudtrail-s3-dynamodb/`)
- `anomai_incidents_api` DynamoDB table exists (partition key: `incident_id`, type String)
- AWS credentials configured in your Codespace

If the `anomai_incidents_api` table does not exist yet:

```bash
aws dynamodb create-table \
  --table-name anomai_incidents_api \
  --attribute-definitions AttributeName=incident_id,AttributeType=S \
  --key-schema AttributeName=incident_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region us-east-2
```

---

## Deploy

### Step 1 — Zip the Lambda handler

Run from inside `infrastructure/detection-pipeline/`:

```bash
zip terraform/lambda.zip lambda_handler.py
```

### Step 2 — Deploy with Terraform

```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

Terraform creates 8 resources:

| Resource | Name |
|---|---|
| `aws_iam_role` | `anomai-pipeline-lambda-role` |
| `aws_iam_role_policy` | `anomai-pipeline-dynamodb` |
| `aws_iam_role` | `anomai-eventbridge-scheduler-role` |
| `aws_iam_role_policy` | `anomai-scheduler-invoke-lambda` |
| `aws_lambda_function` | `anomai-pipeline` |
| `aws_lambda_permission` | `AllowEventBridgeScheduler` |
| `aws_scheduler_schedule` | `anomai-pipeline-every-5-min` |
| `aws_cloudwatch_log_group` | `/aws/lambda/anomai-pipeline` |

---

## Test it immediately

After `terraform apply`, invoke the Lambda manually without waiting 5 minutes:

```bash
aws lambda invoke \
  --function-name anomai-pipeline \
  --region us-east-2 \
  response.json && cat response.json
```

Expected response:

```json
{
  "statusCode": 200,
  "body": "{\"events_scanned\": 7192, \"incidents_detected\": 11, \"new_written\": 0, \"skipped_existing\": 11, \"elapsed_seconds\": 14.3}"
}
```

`new_written: 0` and `skipped_existing: 11` on a re-run is correct — the
pipeline detected the same 11 incidents but skipped writing them because they
already exist in the table.

---

## Check logs

```bash
aws logs tail /aws/lambda/anomai-pipeline --follow --region us-east-2
```

Each invocation logs:

```
AnomAI pipeline starting — source=anomai_events dest=anomai_incidents_api lookback=120d
Scanned 7192 events (cutoff 2025-11-25)
Done — events=7192 detected=11 new=0 skipped=11 elapsed=14.3s
```

---

## Configuration

All config is passed through environment variables set in Terraform.
No secrets or values are hardcoded in the Lambda code.

| Variable | Default | Description |
|---|---|---|
| `ANOMAI_SOURCE_TABLE` | `anomai_events` | DynamoDB table to scan for events |
| `ANOMAI_DEST_TABLE` | `anomai_incidents_api` | DynamoDB table to write incidents to |
| `ANOMAI_LOOKBACK_DAYS` | `120` | Days of events to scan on each run |

To change any value, update `terraform/main.tf` variables and run
`terraform apply` again.

---

## Changing the schedule

Default is every 5 minutes. To change it, edit `terraform/main.tf`:

```hcl
variable "schedule_minutes" {
  default = 15  # change to any interval
}
```

Then run `terraform apply`.

---

## IAM permissions

The Lambda role is least-privilege — only the exact actions the pipeline needs:

| Permission | Table | Why |
|---|---|---|
| `dynamodb:Scan` | `anomai_events` | Read source events |
| `dynamodb:Scan` | `anomai_incidents_api` | Check for existing incidents |
| `dynamodb:PutItem` | `anomai_incidents_api` | Write new incidents |
| `dynamodb:GetItem` | `anomai_incidents_api` | Reserved for future use |
| `logs:CreateLogGroup/Stream/Events` | — | Write to CloudWatch |

---

## Teardown

To remove all resources created by this Terraform:

```bash
cd terraform/
terraform destroy
```

This does **not** delete the DynamoDB tables or their data.

---

## Troubleshooting

**Lambda times out**

Your `anomai_events` table has grown large and the 120-day scan takes
longer than 5 minutes. Increase the timeout in `terraform/main.tf`:

```hcl
variable "lambda_timeout_seconds" {
  default = 600  # max is 900
}
```

Then either reduce `lookback_days` or increase `schedule_minutes` to match.

**`ConditionalCheckFailedException` in logs**

This is expected and not an error. It means the incident already exists in
`anomai_incidents_api` and the duplicate write was correctly blocked.

**No incidents appearing in the API or dashboard**

1. Check Lambda logs: `aws logs tail /aws/lambda/anomai-pipeline --follow`
2. Verify the destination table has data:
   `aws dynamodb scan --table-name anomai_incidents_api --max-items 3`
3. Confirm the Flask API is running and pointing at the right table