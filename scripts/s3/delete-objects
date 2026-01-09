#!/usr/bin/env bash
# delete-objects.sh — remove all objects from a given S3 bucket
#
# Usage:
#   ./delete-objects.sh <bucket-name>
#   Example: ./delete-objects.sh my-bucket
#
# Description:
#   Deletes every object (and version, if enabled) inside the specified bucket.
#   This action is irreversible, so confirmation is required before execution.

echo "== delete objects"

# Exit immediately if a command fails
set -e

# --- Input validation --------------------------------------------------------
if [ -z "$1" ]; then
  echo "Bucket name is required. Example: ./delete-objects.sh my-bucket"
  exit 1
fi

BUCKET_NAME="$1"

# --- User confirmation -------------------------------------------------------
echo "WARNING: This will permanently delete ALL objects in s3://$BUCKET_NAME"
read -p "Are you sure? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Cancelled."
  exit 0
fi

echo "Deleting all objects from s3://$BUCKET_NAME ..."
echo

# --- Perform deletion --------------------------------------------------------
aws s3 rm "s3://$BUCKET_NAME" --recursive

echo
echo "All objects deleted from s3://$BUCKET_NAME"