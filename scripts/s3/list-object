#!/usr/bin/env bash
# list-objects.sh — list all objects in a given S3 bucket
#
# Usage:
#   ./list-objects.sh <bucket-name>
#   Example: ./list-objects.sh my-bucket
#
# Description:
#   Displays all objects stored in the specified S3 bucket.
#   Uses `aws s3api list-objects-v2` for full API-level control.
#   Automatically handles empty buckets gracefully.

echo "== list objects"

# Exit immediately if any command fails
set -e

# --- Input validation --------------------------------------------------------
if [ -z "$1" ]; then
  echo "Bucket name is required. Example: ./list-objects.sh my-bucket"
  exit 1
fi

BUCKET_NAME="$1"

# --- Fetch object list -------------------------------------------------------
echo "Fetching object list from bucket: $BUCKET_NAME"
echo

RESULT=$(aws s3api list-objects-v2 --bucket "$BUCKET_NAME" --query 'Contents[].Key' --output text 2>/dev/null || true)

# --- Display results ---------------------------------------------------------
if [ -z "$RESULT" ]; then
  echo "(Bucket is empty or does not exist)"
else
  echo "$RESULT" | tr '\t' '\n'
fi