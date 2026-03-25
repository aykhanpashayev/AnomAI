# CloudTrail Parser

Development utility for parsing raw CloudTrail `.json.gz` log files into
normalized JSONL. Used during early development to understand the CloudTrail
log format and validate the normalization logic before it was built into the
ingest Lambda.

> **Note:** In production, this parsing happens automatically inside the
> ingest Lambda (`infrastructure/auto-ingestion/`). This script is useful
> for local inspection and debugging of raw CloudTrail files.

---

## Files

| File | Description |
|---|---|
| `parse_cloudtrail.py` | Parser script — reads `.json.gz` or `.json` files, outputs normalized JSONL |
| `cloudtrail_sample.json` | Small sample CloudTrail file for testing |

---

## Usage

```bash
# Parse a single file
python3 parse_cloudtrail.py path/to/cloudtrail.json.gz

# Parse all CloudTrail files in a folder
python3 parse_cloudtrail.py path/to/logs/

# Custom output path
python3 parse_cloudtrail.py cloudtrail_sample.json -o my_output.jsonl

# Keep requestParameters and responseElements (dropped by default to save space)
python3 parse_cloudtrail.py cloudtrail_sample.json --keep-heavy-fields

# Print more sample events to stdout (default: 3)
python3 parse_cloudtrail.py cloudtrail_sample.json --print-sample 10

# Skip access key masking (not recommended)
python3 parse_cloudtrail.py cloudtrail_sample.json --no-mask-keys
```

---

## CLI flags

| Flag | Default | Description |
|---|---|---|
| `input` | — | Path to a `.json` / `.json.gz` file, or a folder |
| `-o`, `--out` | `normalized.jsonl` | Output JSONL file path |
| `--keep-heavy-fields` | off | Keep `requestParameters` and `responseElements` |
| `--no-mask-keys` | off | Do not mask `accessKeyId` values |
| `--print-sample` | `3` | Number of normalized events to print to stdout |

---

## Output format

Each line in the output JSONL file is one normalized event:

```json
{
  "userType": "AssumedRole",
  "userArn": "arn:aws:sts::<account-id>:assumed-role/<role>/<session>",
  "accountId": "<account-id>",
  "accessKeyId": "****************XXXX",
  "roleName": "AWSReservedSSO_AnomAIAdmin_...",
  "sessionName": "Alice",
  "actor": "Alice",
  "mfaAuthenticated": false,
  "eventName": "DescribeRegions",
  "eventSource": "ec2.amazonaws.com",
  "eventType": "AwsApiCall",
  "readOnly": true,
  "awsRegion": "us-east-2",
  "eventTime": "2026-01-19T16:10:31Z",
  "eventID": "314baed6-...",
  "sourceIPAddress": "1.2.3.4",
  "errorCode": null,
  "errorMessage": null,
  "tlsDetails": { "tlsVersion": "TLSv1.3", ... }
}
```

### Key fields

| Field | Description |
|---|---|
| `actor` | Best-effort human identity — resolved from `userName`, session name, or principal ID. This is what the detection pipeline baselines on |
| `accessKeyId` | Masked by default — last 4 characters only |
| `requestParameters` / `responseElements` | Dropped by default — can double the record size. Use `--keep-heavy-fields` to retain |

---

## Console summary

After parsing, the script prints a summary to stdout:

```
--- Summary ---
Total normalized events: 10
Files with errors: 0

Top eventSource:
  cloudtrail.amazonaws.com: 8
  ec2.amazonaws.com: 1

Top eventName:
  LookupEvents: 2
  DescribeTrails: 2
  ...

Top actor:
  Alice: 10

Wrote JSONL: normalized.jsonl
Heavy fields: DROPPED (requestParameters/responseElements)
```