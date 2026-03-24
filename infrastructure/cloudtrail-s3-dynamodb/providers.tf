# Terraform configuration block
terraform {
  # Tell Terraform which providers we need
  required_providers {
    aws = {
      source  = "hashicorp/aws"   # Official AWS provider
      version = "~> 5.0"          # Any 5.x version (safe, stable)
    }
  }
}

# AWS provider configuration
# Terraform will automatically use AWS credentials from environment variables
provider "aws" {
  region = "us-east-2"  # Change if you want another region
}
