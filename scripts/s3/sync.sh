#!/usr/bin/env bash
# s3-sync-sample.sh — generate 5–10 small text files locally and upload to s3://<bucket>/files
#
# Usage:
#   ./s3-sync-sample.sh <bucket-name> <file-prefix>
#   Example: ./s3-sync-sample.sh my-bucket files
#
# Notes:
# - Creates files under /tmp/s3-bash-scripts
# - File names: <prefix>_N.txt (1–3 KB each)
# - Uploads to s3://<bucket>/files

echo "== sync"

# Exit on first failure (simple + predictable)
set -e

# --- Input validation (same interface: 2 args) ------------------------------
if [ -z "$1" ]; then
  echo "Bucket name is needed. Example: ./s3-sync-sample.sh my-bucket files"
  exit 1
fi
if [ -z "$2" ]; then
  echo "Filename prefix is needed."
  exit 1
fi

BUCKET_NAME="$1"
FILENAME_PREFIX="$2"

# --- Local workspace --------------------------------------------------------
OUTPUT_DIR="/tmp/s3-bash-scripts"
rm -rf "$OUTPUT_DIR" 2>/dev/null || true
mkdir -p "$OUTPUT_DIR"

# Random 5–10 files
NUM_FILES=$((RANDOM % 6 + 5))

echo "Output directory: $OUTPUT_DIR"
echo "Number of files to create: $NUM_FILES"
echo

# --- Generate files ---------------------------------------------------------
for i in $(seq 1 "$NUM_FILES"); do
  FILE="$OUTPUT_DIR/${FILENAME_PREFIX}_$i.txt"
  SIZE_KB=$((RANDOM % 3 + 1))   # 1–3 KB
  # Avoid SIGPIPE: read N bytes first, then base64-encode
  head -c $((SIZE_KB * 1024)) </dev/urandom | base64 > "$FILE"
  echo "Created $FILE (${SIZE_KB}KB)"
done

echo
echo "All $NUM_FILES files created successfully in $OUTPUT_DIR!"

# Show a tree if available (fallback to ls)
if command -v tree >/dev/null 2>&1; then
  tree "$OUTPUT_DIR" || true
else
  ls -l "$OUTPUT_DIR"
fi

# --- Upload to S3 (same destination/prefix) ---------------------------------
# Use one of the two lines below. Keep only ONE active.
# 1) Clean output:
aws s3 sync "$OUTPUT_DIR" "s3://$BUCKET_NAME/files" --only-show-errors --exact-timestamps
# 2) Classic progress bar:
# aws s3 sync "$OUTPUT_DIR" "s3://$BUCKET_NAME/files" --progress --exact-timestamps