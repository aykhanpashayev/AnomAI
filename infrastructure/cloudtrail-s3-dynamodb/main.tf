#############################################
# S3 BUCKET FOR CLOUDTRAIL LOGS
#############################################

# Create an S3 bucket where CloudTrail logs will be stored
resource "aws_s3_bucket" "logs" {
  bucket        = "anomai-cloudtrail-logs-dev"  # Must be globally unique
  force_destroy = true                          # Allows bucket deletion even if it has files (dev only!)
}

#############################################
# DATA SOURCES (READ-ONLY AWS INFO)
#############################################

# Get current AWS account ID and caller info
data "aws_caller_identity" "current" {}

# Get AWS partition (aws, aws-us-gov, aws-cn)
data "aws_partition" "current" {}

# Get the AWS region name dynamically
data "aws_region" "current" {}

#############################################
# S3 BUCKET POLICY (ALLOW CLOUDTRAIL ACCESS)
#############################################

# Attach a bucket policy to the S3 bucket
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs.json
}

# IAM policy document defining what CloudTrail is allowed to do
data "aws_iam_policy_document" "logs" {

  # Statement 1:
  # Allow CloudTrail to check the bucket's ACL
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    # Only the CloudTrail service is allowed
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    # Permission CloudTrail needs to verify bucket ownership
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    # Restrict permission to THIS specific CloudTrail
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/anomai-dev"
      ]
    }
  }

  # Statement 2:
  # Allow CloudTrail to upload log files into the bucket
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    # Allow CloudTrail to upload objects (log files)
    actions   = ["s3:PutObject"]

    # Logs are written under AWSLogs/<account-id>/
    resources = [
      "${aws_s3_bucket.logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
    ]

    # Required condition for CloudTrail log delivery
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    # Again, restrict access to ONLY this CloudTrail
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:${data.aws_partition.current.partition}:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/anomai-dev"
      ]
    }
  }
}

#############################################
# CLOUDTRAIL
#############################################

# Create CloudTrail to log AWS API activity
resource "aws_cloudtrail" "trail" {

  # Ensure bucket policy exists BEFORE CloudTrail starts
  depends_on = [aws_s3_bucket_policy.logs]

  name           = "anomai-dev"                 # CloudTrail name
  s3_bucket_name = aws_s3_bucket.logs.id        # Where logs are stored

  include_global_service_events = true          # Log IAM, STS, etc.
  is_multi_region_trail         = true          # Log events from all regions
  enable_logging                = true          # Start logging immediately
}

#############################################
# DYNAMODB TABLES (STORAGE LAYER)
#############################################

# Table to optionally store normalized CloudTrail events
resource "aws_dynamodb_table" "events" {
  name         = "anomai_events"
  billing_mode = "PAY_PER_REQUEST"  # No capacity management
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"  # String
  }
}

# Table to store learned baselines (normal behavior)
resource "aws_dynamodb_table" "baselines" {
  name         = "anomai_baselines"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "baseline_id"

  attribute {
    name = "baseline_id"
    type = "S"
  }
}

# Table to store detected incidents/anomalies
resource "aws_dynamodb_table" "incidents" {
  name         = "anomai_incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }
}
