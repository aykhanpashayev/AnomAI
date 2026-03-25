#!/usr/bin/env bash
# list-buckets — show your S3 buckets (newest first), with handy filters
#
# Examples:
#   ./list-buckets
#   ./list-buckets --prefix prod-
#   ./list-buckets -n 10 --names-only -p work
#
# Notes:
# - S3 is global, but we still respect --profile for the AWS account.
# - Newest buckets appear first (reverse sort by CreationDate).

set -Eeuo pipefail
IFS=$'\n\t'

print_usage() {
  cat <<'USAGE'
Usage: list-buckets [options]

Options:
  -p, --profile PROFILE   AWS CLI profile to use
  --prefix PREFIX         Only show buckets whose names start with PREFIX
  -n, --top N             Limit output to top N buckets (after filtering)
  --names-only            Print only bucket names (useful for scripting)
  -q, --quiet             Suppress non-error info messages
  -h, --help              Show this help

Examples:
  list-buckets
  list-buckets --prefix app-
  list-buckets -n 5 --names-only -p personal
USAGE
}

# --- helpers ---------------------------------------------------------------
err() { printf "Error: %s\n" "$*" >&2; }
info() { [ "${QUIET:-0}" = "1" ] || printf "%s\n" "$*"; }
require() {
  command -v "$1" >/dev/null 2>&1 || { err "Missing dependency: $1 (install AWS CLI v2)"; exit 127; }
}

is_integer() { [[ "$1" =~ ^[0-9]+$ ]]; }

# --- parse args ------------------------------------------------------------
PROFILE=""
PREFIX=""
TOP=""
NAMES_ONLY=0
QUIET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--profile) PROFILE="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -n|--top) TOP="$2"; shift 2 ;;
    --names-only) NAMES_ONLY=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    *) err "Unknown option: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -n "$TOP" && ! $(is_integer "$TOP" && echo true) ]]; then
  err "--top requires a positive integer"; exit 2
fi

require aws

info "== list buckets (newest first)"
[ -n "$PROFILE" ] && info "Profile: $PROFILE"
[ -n "$PREFIX" ] && info "Filter : names starting with '$PREFIX'"
[ -n "$TOP" ] && info "Top    : $TOP"

# Pull name + creation timestamp, newest first (no stray None)
# Output is tab-separated: "<Name>\t<CreationDate>"
mapfile -t BUCKET_ROWS < <(
  aws ${PROFILE:+--profile "$PROFILE"} s3api list-buckets \
    --query 'reverse(sort_by(Buckets, &CreationDate))[].[Name, CreationDate]' \
    --output text | awk 'NF'
)

# If no buckets, exit nicely
if [[ ${#BUCKET_ROWS[@]} -eq 0 ]]; then
  info "No buckets found."
  exit 0
fi

# Filter and limit
filtered=()
for row in "${BUCKET_ROWS[@]}"; do
  # row: "name<TAB>2025-10-10T15:14:03+00:00"
  name="${row%%$'\t'*}"
  created="${row#*$'\t'}"

  # Skip any odd lines defensively
  [[ -z "$name" || "$name" == "None" || "$created" == "None" ]] && continue

  if [[ -n "$PREFIX" && "$name" != "$PREFIX"* ]]; then
    continue
  fi
  filtered+=("$row")
done

if [[ -n "$TOP" ]]; then
  # Keep only first N entries after filtering
  tmp=()
  count=0
  for row in "${filtered[@]}"; do
    tmp+=("$row")
    ((count++))
    [[ $count -ge $TOP ]] && break
  done
  filtered=("${tmp[@]}")
fi

# --- Output ---------------------------------------------------------------
if [[ ${#filtered[@]} -eq 0 ]]; then
  info "No buckets matched your filters."
  exit 0
fi

if [[ $NAMES_ONLY -eq 1 ]]; then
  # Just names, one per line
  for row in "${filtered[@]}"; do
    printf "%s\n" "${row%%$'\t'*}"
  done
  exit 0
fi

# Pretty table: CREATED (UTC) | BUCKET
printf "%-25s  %s\n" "CREATED (UTC)" "BUCKET"
printf "%-25s  %s\n" "-------------------------" "------------------------------"
for row in "${filtered[@]}"; do
  name="${row%%$'\t'*}"
  created="${row#*$'\t'}"
  # Normalize display: if it ends with Z, make it explicit +00:00
  created="${created/Z/+00:00}"
  printf "%-25s  %s\n" "$created" "$name"
done