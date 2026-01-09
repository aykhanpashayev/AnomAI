#!/usr/bin/env bash
# create-bucket — create an S3 bucket safely with sane defaults
#
# Examples:
#   ./create-bucket my-logs-bucket-123
#   ./create-bucket my-logs-bucket-123 -r us-west-2 -p personal --enable-versioning
#
# Notes:
# - If REGION is us-east-1, CreateBucketConfiguration must be omitted (AWS quirk).
# - We default to blocking public access. You can opt out with --no-block-public.
# - Respects AWS_PROFILE / AWS_REGION if flags aren’t provided.

set -Eeuo pipefail
IFS=$'\n\t'

print_usage() {
  cat <<'USAGE'
Usage: create-bucket <bucket-name> [options]

Options:
  -r, --region REGION        AWS region (default: $AWS_REGION or CLI config)
  -p, --profile PROFILE      AWS CLI profile to use
      --enable-versioning    Turn on bucket versioning after creation
      --no-block-public      Do NOT enable "Block Public Access" (defaults to ON)
  -q, --quiet                Only print the final bucket URL on success
  -h, --help                 Show this help

Examples:
  create-bucket my-bucket-123
  create-bucket my-bucket-123 -r us-west-2 -p work --enable-versioning
USAGE
}

# --- small helpers -----------------------------------------------------------
err() { printf "Error: %s\n" "$*" >&2; }
info() { [ "${QUIET:-0}" = "1" ] || printf "%s\n" "$*"; }

require() {
  command -v "$1" >/dev/null 2>&1 || {
    err "Missing dependency: $1 (install AWS CLI v2: https://docs.aws.amazon.com/cli/latest/userguide/)"; exit 127;
  }
}

bucket_name_regex='^([a-z0-9]([a-z0-9-]{1,61}[a-z0-9])?)$'

validate_bucket_name() {
  local name="$1"
  # Basic DNS-style checks (good enough for most cases; S3 adds a few edge-case rules)
  if [[ ${#name} -lt 3 || ${#name} -gt 63 ]]; then
    err "Bucket name must be 3–63 chars."; return 1
  fi
  if [[ ! "$name" =~ $bucket_name_regex ]]; then
    err "Bucket name must be lowercase letters, digits, and hyphens (no leading/trailing hyphen)."; return 1
  fi
  if [[ "$name" == *".."* || "$name" == *".-"* || "$name" == *"-."* ]]; then
    err "Bucket name cannot look like an IP or contain adjacent dots/hyphen-dot combos."; return 1
  fi
}

# --- parse args --------------------------------------------------------------
PROFILE=""
REGION="${AWS_REGION:-}"
ENABLE_VERSIONING=0
BLOCK_PUBLIC=1
QUIET=0

if [[ $# -eq 0 ]]; then print_usage; exit 1; fi
BUCKET="$1"; shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--region) REGION="$2"; shift 2 ;;
    -p|--profile) PROFILE="$2"; shift 2 ;;
    --enable-versioning) ENABLE_VERSIONING=1; shift ;;
    --no-block-public) BLOCK_PUBLIC=0; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) print_usage; exit 0 ;;
    *) err "Unknown option: $1"; print_usage; exit 1 ;;
  esac
done

# --- preflight ---------------------------------------------------------------
require aws

# If region not provided, fall back to configured default
if [[ -z "${REGION}" ]]; then
  # shellcheck disable=SC2016
  REGION="$(aws ${PROFILE:+--profile "$PROFILE"} configure get region || true)"
fi
if [[ -z "${REGION}" ]]; then
  err "No region set. Use --region or export AWS_REGION, or set a default with: aws configure set region <region>"
  exit 2
fi

validate_bucket_name "$BUCKET" || exit 2

info "== create bucket"
info "Bucket : $BUCKET"
info "Region : $REGION"
[ -n "$PROFILE" ] && info "Profile: $PROFILE"

# Quick probe: if you have access and it already exists, bail out early with a friendly message.
if aws ${PROFILE:+--profile "$PROFILE"} s3api head-bucket --bucket "$BUCKET" 2>/dev/null; then
  err "Bucket already exists and you have access: $BUCKET"
  exit 10
fi

# --- create bucket -----------------------------------------------------------
create_args=( s3api create-bucket --bucket "$BUCKET" )
# us-east-1 must NOT include CreateBucketConfiguration
if [[ "$REGION" != "us-east-1" ]]; then
  create_args+=( --create-bucket-configuration LocationConstraint="$REGION" )
fi

# Include region and profile in the CLI invocation
aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" "${create_args[@]}" >/dev/null

# --- harden defaults ---------------------------------------------------------
if [[ $BLOCK_PUBLIC -eq 1 ]]; then
  aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api put-public-access-block \
    --bucket "$BUCKET" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true >/dev/null
  info "✓ Block Public Access: enabled"
else
  info "⚠️ Block Public Access: NOT enabled (you opted out)"
fi

if [[ $ENABLE_VERSIONING -eq 1 ]]; then
  aws ${PROFILE:+--profile "$PROFILE"} --region "$REGION" s3api put-bucket-versioning \
    --bucket "$BUCKET" --versioning-configuration Status=Enabled >/dev/null
  info "✓ Versioning: enabled"
fi

# Small wait to avoid eventual-consistency surprises on immediate follow-up ops
sleep 1

# --- output ------------------------------------------------------------------
ARN="arn:aws:s3:::${BUCKET}"
URI="s3://${BUCKET}"
LOC_URL="https://s3.${REGION}.amazonaws.com/${BUCKET}"

if [[ "$REGION" == "us-east-1" ]]; then
  LOC_URL="https://s3.amazonaws.com/${BUCKET}"
fi

[ "$QUIET" = "1" ] && { printf "%s\n" "$LOC_URL"; exit 0; }

info "✓ Bucket created"
info "  ARN : ${ARN}"
info "  URI : ${URI}"
info "  URL : ${LOC_URL}"