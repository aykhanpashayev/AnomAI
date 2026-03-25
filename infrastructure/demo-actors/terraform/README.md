# Demo Actor Roles

Three IAM roles used for generating realistic CloudTrail activity to test
and demonstrate the AnomAI detectors. Each role has a different permission
set that makes it suitable for triggering specific incident types.

---

## Roles

| Role | Persona | Permissions | Triggers |
|---|---|---|---|
| `anomai-demo-alice` | Normal developer | Broad read-only (EC2, S3, IAM, DynamoDB, Lambda, CloudWatch) | Baseline activity, API Burst |
| `anomai-demo-arthur` | Suspicious insider | Broader read + IAM list/describe + KMS Decrypt | API Burst, Access Denied Spike |
| `anomai-demo-john` | External attacker | Minimal — only `sts:GetCallerIdentity` and `ec2:DescribeRegions` | Access Denied Spike, New Region Activity |

The trust policy on all three roles allows any IAM principal in your AWS
account to assume them — this is what makes them assumable from your Codespace.

---

## Deploy

```bash
cd infrastructure/demo-actors/terraform/
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set your account ID:

```hcl
aws_region = "us-east-2"
account_id = "YOUR_ACCOUNT_ID"
```

Then deploy:

```bash
terraform init
terraform plan
terraform apply
```

The role ARNs are printed as outputs when apply completes:

```
Outputs:

alice_role_arn  = "arn:aws:iam::123456789012:role/anomai-demo-alice"
arthur_role_arn = "arn:aws:iam::123456789012:role/anomai-demo-arthur"
john_role_arn   = "arn:aws:iam::123456789012:role/anomai-demo-john"
```

---

## Assume a role

```bash
# Assume the role
aws sts assume-role \
  --role-arn arn:aws:iam::<account-id>:role/anomai-demo-alice \
  --role-session-name alice-session

# Export the returned credentials
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<SessionToken>

# Verify
aws sts get-caller-identity
# Should show anomai-demo-alice in the Arn field
```

Replace `anomai-demo-alice` with `anomai-demo-arthur` or `anomai-demo-john`
for the other roles.

---

## Generate activity

With a role assumed, run the activity generator from the repo root:

```bash
# Access denied spike (works best with john — almost everything is denied)
bash scripts/activity_generator/generate_activity.sh \
  --scenario access_denied_spike --duration 120 --rate 90

# API burst (works best with alice or arthur — calls succeed at high volume)
bash scripts/activity_generator/generate_activity.sh \
  --scenario burst_api_calls --duration 120 --rate 180

# New region activity (hits multiple regions)
bash scripts/activity_generator/generate_activity.sh \
  --scenario new_region --duration 180 \
  --regions "us-east-1,eu-west-1,ap-southeast-1"

# Mixed — runs all scenarios in sequence
bash scripts/activity_generator/generate_activity.sh \
  --scenario mixed --duration 300
```

Wait approximately 5 minutes after the script finishes for the detection
Lambda to pick up the new events and write incidents to DynamoDB.

---

## Go back to your normal credentials

```bash
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN
```

---

## Teardown

```bash
terraform destroy
```