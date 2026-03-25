# CloudTrail + S3 + DynamoDB

Base infrastructure for AnomAI. Provisions the AWS resources that capture
every API call made in the account and store the data for anomaly detection.

This is the first thing to deploy — everything else depends on it.

---

## What it creates

| Resource | Name | Purpose |
|---|---|---|
| `aws_s3_bucket` | `anomai-cloudtrail-logs-dev` | Receives compressed CloudTrail log files |
| `aws_s3_bucket_policy` | — | Grants CloudTrail permission to write to the bucket |
| `aws_cloudtrail` | `anomai-dev` | Multi-region trail — captures all AWS API activity |
| `aws_dynamodb_table` | `anomai_events` | Stores normalized CloudTrail events (PK: `event_id`) |
| `aws_dynamodb_table` | `anomai_incidents` | Stores detected incidents (PK: `incident_id`) |
| `aws_dynamodb_table` | `anomai_baselines` | Reserved for baseline storage (PK: `baseline_id`) |

### CloudTrail configuration

- **Multi-region** — captures events from all AWS regions, not just `us-east-2`
- **Global service events** — includes IAM, STS, and other global services
- **Logging enabled immediately** — starts capturing as soon as `apply` completes
- **S3 bucket policy** — scoped to only the `anomai-dev` trail via `aws:SourceArn`
  condition, so no other trail can write to this bucket

### DynamoDB billing

All three tables use `PAY_PER_REQUEST` — no capacity planning needed, costs
scale with actual usage.

---

## Deploy

```bash
cd infrastructure/cloudtrail-s3-dynamodb/
terraform init
terraform plan
terraform apply
```

No variables required — region is set to `us-east-2` in `providers.tf`.
To use a different region, update the `region` field in `providers.tf` before
running `terraform apply`.

---

## Verify

Check that CloudTrail is active:

```bash
aws cloudtrail get-trail-status --name anomai-dev --region us-east-2 \
  --query 'IsLogging'
# Expected: true
```

After 5–15 minutes, confirm logs are being delivered to S3:

```bash
aws s3 ls s3://anomai-cloudtrail-logs-dev/AWSLogs/ --recursive | head -5
```

---

## Next steps

Once this is deployed:

1. Deploy the ingest Lambda → `infrastructure/auto-ingestion/`
   This wires up the S3 trigger that parses logs into `anomai_events`

2. Deploy the detection pipeline → `infrastructure/detection-pipeline/`
   This runs anomaly detection every 5 minutes and writes to `anomai_incidents_api`

Note: `anomai_incidents_api` is created separately — either by the detection
pipeline Terraform or manually. It is not part of this module.

---

## Teardown

```bash
terraform destroy
```

The S3 bucket has `force_destroy = true` so Terraform will delete it along
with all log files inside it. This is intentional for a dev environment —
remove that flag before using this in production.