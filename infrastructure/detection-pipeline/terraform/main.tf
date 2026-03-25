# =============================================================
# AnomAI — Lambda + EventBridge Scheduler (every 5 minutes)
# =============================================================
#
# What this creates:
#   - IAM role for the Lambda (least-privilege DynamoDB access)
#   - Lambda function (Python 3.12, 256MB, 5-min timeout)
#   - EventBridge Scheduler rule (rate(5 minutes))
#   - CloudWatch Log Group with 14-day retention
#
# Prerequisites:
#   - Your lambda_handler.py zipped as lambda.zip in this directory
#   - AWS credentials configured (via env vars or ~/.aws/credentials)
#
# Usage:
#   terraform init
#   terraform plan
#   terraform apply
# =============================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}


# -------------------------------------------------------------
# Variables
# -------------------------------------------------------------

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-2"
}

variable "source_table" {
  description = "DynamoDB source table name (CloudTrail events)"
  type        = string
  default     = "anomai_events"
}

variable "dest_table" {
  description = "DynamoDB destination table name (API incidents)"
  type        = string
  default     = "anomai_incidents_api"
}

variable "lookback_days" {
  description = "How many days of events to scan on each run"
  type        = number
  default     = 120
}

variable "schedule_minutes" {
  description = "How often to run the pipeline (in minutes)"
  type        = number
  default     = 5
}

variable "lambda_memory_mb" {
  description = "Lambda memory in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = "Lambda timeout in seconds (max 900). Set higher if your table is large."
  type        = number
  default     = 300
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 14
}


# -------------------------------------------------------------
# Data sources
# -------------------------------------------------------------

data "aws_caller_identity" "current" {}


# -------------------------------------------------------------
# IAM Role for Lambda
# -------------------------------------------------------------

resource "aws_iam_role" "anomai_lambda" {
  name = "anomai-pipeline-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = "AnomAI" }
}

# Least-privilege DynamoDB policy — only what the pipeline actually needs
resource "aws_iam_role_policy" "anomai_dynamodb" {
  name = "anomai-pipeline-dynamodb"
  role = aws_iam_role.anomai_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read from source events table
        Sid    = "ReadSourceTable"
        Effect = "Allow"
        Action = ["dynamodb:Scan"]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.source_table}"
      },
      {
        # Read + write to destination incidents table
        Sid    = "ReadWriteDestTable"
        Effect = "Allow"
        Action = [
          "dynamodb:Scan",
          "dynamodb:PutItem",
          "dynamodb:GetItem",
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${data.aws_caller_identity.current.account_id}:table/${var.dest_table}"
      },
      {
        # Write logs to CloudWatch
        Sid    = "WriteLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/anomai-pipeline:*"
      },
    ]
  })
}


# -------------------------------------------------------------
# CloudWatch Log Group (with retention so logs don't accumulate forever)
# -------------------------------------------------------------

resource "aws_cloudwatch_log_group" "anomai_lambda" {
  name              = "/aws/lambda/anomai-pipeline"
  retention_in_days = var.log_retention_days
  tags              = { Project = "AnomAI" }
}


# -------------------------------------------------------------
# Lambda Function
# -------------------------------------------------------------

resource "aws_lambda_function" "anomai_pipeline" {
  function_name = "anomai-pipeline"
  description   = "AnomAI detection pipeline — scans CloudTrail events and writes incidents to DynamoDB"

  # Your zipped handler — see "How to deploy" section below
  filename         = "${path.module}/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/lambda.zip")

  runtime     = "python3.12"
  handler     = "lambda_handler.lambda_handler"
  role        = aws_iam_role.anomai_lambda.arn
  memory_size = var.lambda_memory_mb
  timeout     = var.lambda_timeout_seconds

  # All config passed as env vars — no secrets in code
  environment {
    variables = {
      ANOMAI_SOURCE_TABLE  = var.source_table
      ANOMAI_DEST_TABLE    = var.dest_table
      ANOMAI_LOOKBACK_DAYS = tostring(var.lookback_days)
    }
  }

  depends_on = [
    aws_iam_role_policy.anomai_dynamodb,
    aws_cloudwatch_log_group.anomai_lambda,
  ]

  tags = { Project = "AnomAI" }
}


# -------------------------------------------------------------
# EventBridge Scheduler — runs every N minutes
# -------------------------------------------------------------

# IAM role that allows EventBridge to invoke the Lambda
resource "aws_iam_role" "scheduler" {
  name = "anomai-eventbridge-scheduler-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "scheduler.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = { Project = "AnomAI" }
}

resource "aws_iam_role_policy" "scheduler_invoke" {
  name = "anomai-scheduler-invoke-lambda"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.anomai_pipeline.arn
    }]
  })
}

resource "aws_scheduler_schedule" "anomai_every_5_min" {
  name        = "anomai-pipeline-every-${var.schedule_minutes}-min"
  description = "Runs the AnomAI detection pipeline every ${var.schedule_minutes} minutes"

  # rate() expression — simple and reliable
  schedule_expression = "rate(${var.schedule_minutes} minutes)"

  # Keep firing even if Lambda is slow — Lambda handles its own dedup
  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.anomai_pipeline.arn
    role_arn = aws_iam_role.scheduler.arn

    # Retry up to 2 times if Lambda fails (e.g. DynamoDB throttle)
    retry_policy {
      maximum_retry_attempts = 2
      maximum_event_age_in_seconds = 300
    }
  }
}

# Allow EventBridge Scheduler to invoke the Lambda
resource "aws_lambda_permission" "allow_scheduler" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.anomai_pipeline.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.anomai_every_5_min.arn
}


# -------------------------------------------------------------
# Outputs
# -------------------------------------------------------------

output "lambda_function_name" {
  description = "Name of the Lambda function"
  value       = aws_lambda_function.anomai_pipeline.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.anomai_pipeline.arn
}

output "scheduler_name" {
  description = "EventBridge Scheduler name"
  value       = aws_scheduler_schedule.anomai_every_5_min.name
}

output "log_group" {
  description = "CloudWatch log group for Lambda logs"
  value       = aws_cloudwatch_log_group.anomai_lambda.name
}
