#!/usr/bin/env bash
# delete-bucket — safely delete an S3 bucket (optionally including all objects)
#
# Examples:
#   ./delete-bucket my-test-bucket
#   ./delete-bucket my-test-bucket -r us-east-2 -p work --force
#
# Notes:
# - Buckets must be empty before deletion unless you use --force.
# - With --force, all objects and versions will be deleted (slow for large buckets).
# - Always prompts for confirmation unless you use --yes.

set -Eeuo pipefail
IFS=$'\n\t'

print_usage() {
  cat <<'USAGE'
Usage: delete-bucket <bucket-name> [options]

Options:
  -r, --region REGION   AWS region (default: $AWS_REGION or CLI config)
  -p, --profile PROFILE AWS CLI profile
  --force               Empty the bucket (including versions) before deleting
  -y, --yes             Skip confirmation prompt (use with caution)
  -q, --quiet           Suppress non-error output
  -h, --help            Show this help and exit

Examples:
  delete-bucket my-bucket
  delete-bucket my-bucket -r us-west-1 -p personal --force -y
USAGE
}

# --- helpers --------------------------------------------------------------
err() { printf "Error: %s\n" "$*" >&2; }
info() { [ "${QUIET:-0}" = "1" ] || printf "%s\n" "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing dependency: $1 (install AWS CLI v2)"; exit 127;
  }
}

confirm() {
  local prompt="$1"
  if [[ "${YES:-0}" = "1" ]]; then return 0; fi
  read -rp "$prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

# --- parse args -----------------------------------------------------------
PROFILE=""
REGION="${AWS_REGION:-}"
FORCE=0
YES=0
QUIET=0

if [[ $# -eq 0 ]]; then print_usage; exit 1; fi
BUCKET="$1"; shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--region) REGION="$2"; shift 2 ;;
    -p|--profile) PROFILE="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    *) err "Unknown option: $1"; print_usage; exit 1 ;;
  esac
done

require aws

if [[ -z "$REGION" ]]; then
  REGION="$(aws ${PROFILE:+--profile "$PROFILE"} configure get region || true)"
fi
if [[ -z "$REGION" ]]; then
  err "Region not set. Use --region or export AWS_REGION."
  exit 2
fi

info "== delete bucket"
info "Bucket : $BUCKET"
info "Region : $REGION"
[ -n "$PROFILE" ] && info "Profile: $PROFILE"

# --- safety check ----------------------------------------------------------
if ! aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  err "Bucket does not exist or you lack access: $BUCKET"
  exit 3
fi

if ! confirm "Are you sure you want to delete bucket '$BUCKET' in $REGION?"; then
  info "Cancelled."
  exit 0
fi

# --- optional force delete -------------------------------------------------
if [[ $FORCE -eq 1 ]]; then
  info "Emptying bucket (this may take a while)..."

  # Delete all object versions and delete markers (safe for versioned buckets)
  aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api delete-objects \
    --bucket "$BUCKET" \
    --delete "$(aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api list-object-versions \
      --bucket "$BUCKET" \
      --output json \
      --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}, Quiet:true}' 2>/dev/null || echo '{"Objects":[]}' )" \
      >/dev/null 2>&1 || true

  # Delete any remaining current objects (non-versioned)
  aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3 rm "s3://${BUCKET}" --recursive >/dev/null 2>&1 || true
  info "✓ Bucket emptied."
fi

# --- delete bucket ---------------------------------------------------------
aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api delete-bucket --bucket "$BUCKET" >/dev/null

info "✓ Bucket deleted successfully: s3://${BUCKET}"