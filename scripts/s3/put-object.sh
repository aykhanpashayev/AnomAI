#!/usr/bin/env bash
# put-object.sh — upload a single local file to an S3 bucket using AWS CLI
#
# Usage:
#   ./put-object.sh <bucket-name> <local-file-path>
#   Example: ./put-object.sh my-bucket ./notes.txt
#
# Description:
#   Takes a local file and uploads it to the specified S3 bucket.
#   The object key will match the filename (basename of the path).
#   Demonstrates use of `aws s3api put-object` for direct API-level uploads.

echo "== put object"

# Exit immediately if any command fails
set -e

# --- Input validation --------------------------------------------------------
if [ -z "$1" ]; then
  echo "Bucket name is required. Example: ./put-object.sh my-bucket ./file.txt"
  exit 1
fi

if [ -z "$2" ]; then
  echo "Filename is required."
  exit 1
fi

BUCKET_NAME="$1"
FILENAME="$2"
OBJECT_KEY=$(basename "$FILENAME")

# --- Check that file exists --------------------------------------------------
if [ ! -f "$FILENAME" ]; then
  echo "Error: File '$FILENAME' not found."
  exit 1
fi

# --- Upload to S3 ------------------------------------------------------------
echo "Uploading '$FILENAME' to s3://$BUCKET_NAME/$OBJECT_KEY ..."
aws s3api put-object \
  --bucket "$BUCKET_NAME" \
  --body "$FILENAME" \
  --key "$OBJECT_KEY"

echo "Upload complete: s3://$BUCKET_NAME/$OBJECT_KEY"