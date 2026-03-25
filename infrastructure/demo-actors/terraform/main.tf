# =============================================================
# AnomAI — Demo Test Actor Roles
# =============================================================
#
# Creates 3 IAM roles that can be assumed from your Codespace:
#   anomai-demo-alice
#   anomai-demo-arthur
#   anomai-demo-john
#
# Usage:
#   terraform init
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
  type    = string
  default = "us-east-2"
}

variable "account_id" {
  description = "Your AWS account ID — set in terraform.tfvars"
  type        = string
}

# -------------------------------------------------------------
# Trust policy — allows any principal in your account to assume
# -------------------------------------------------------------

locals {
  trust_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = {
        AWS = "arn:aws:iam::${var.account_id}:root"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# -------------------------------------------------------------
# anomai-demo-alice
# -------------------------------------------------------------

resource "aws_iam_role" "alice" {
  name               = "anomai-demo-alice"
  assume_role_policy = local.trust_policy
  tags               = { Project = "AnomAI" }
}

resource "aws_iam_role_policy" "alice" {
  name = "anomai-demo-alice-policy"
  role = aws_iam_role.alice.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:GetCallerIdentity",
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:ListBucket",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "iam:GetRole",
        "cloudtrail:LookupEvents",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "cloudwatch:DescribeAlarms",
      ]
      Resource = "*"
    }]
  })
}

# -------------------------------------------------------------
# anomai-demo-arthur
# -------------------------------------------------------------

resource "aws_iam_role" "arthur" {
  name               = "anomai-demo-arthur"
  assume_role_policy = local.trust_policy
  tags               = { Project = "AnomAI" }
}

resource "aws_iam_role_policy" "arthur" {
  name = "anomai-demo-arthur-policy"
  role = aws_iam_role.arthur.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:GetCallerIdentity",
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "iam:ListUsers",
        "iam:ListPolicies",
        "iam:GetRole",
        "iam:GetPolicy",
        "dynamodb:DescribeTable",
        "dynamodb:ListTables",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:DescribeContinuousBackups",
        "lambda:ListFunctions",
        "lambda:GetFunction",
        "cloudwatch:DescribeAlarms",
        "cloudtrail:LookupEvents",
        "kms:Decrypt",
      ]
      Resource = "*"
    }]
  })
}

# -------------------------------------------------------------
# anomai-demo-john
# -------------------------------------------------------------

resource "aws_iam_role" "john" {
  name               = "anomai-demo-john"
  assume_role_policy = local.trust_policy
  tags               = { Project = "AnomAI" }
}

resource "aws_iam_role_policy" "john" {
  name = "anomai-demo-john-policy"
  role = aws_iam_role.john.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
      ]
      Resource = "*"
    }]
  })
}

# -------------------------------------------------------------
# Outputs
# -------------------------------------------------------------

output "alice_role_arn" {
  value = aws_iam_role.alice.arn
}

output "arthur_role_arn" {
  value = aws_iam_role.arthur.arn
}

output "john_role_arn" {
  value = aws_iam_role.john.arn
}
