#!/usr/bin/env bash
# scripts/generate_activity.sh
# AnomAI traffic generator: creates REAL AWS API activity so CloudTrail -> S3 -> Lambda -> DynamoDB works.
#
# IMPORTANT UX CHANGE:
# - This script WILL NOT run unless you pass --scenario.
# - If you forget args, it prints exact commands to run and exits.

set -euo pipefail

# -----------------------------
# Defaults (only used IF args provided)
# -----------------------------
SCENARIO=""
DURATION=300            # seconds
RATE=60                 # approx calls/min (best effort)
REGIONS="us-east-1,us-west-2"
LOG_DIR="./logs"
QUIET=1                 # 1 = hide aws output, 0 = show
LOG_BUCKET="anomai-cloudtrail-logs-dev"

# -----------------------------
# Helpers
# -----------------------------
usage() {
  cat <<'EOF'
AnomAI Activity Generator (CloudTrail → S3 → Lambda → DynamoDB)

REQUIRED:
  --scenario <baseline|burst_api_calls|new_region|access_denied_spike|mixed>

OPTIONAL:
  --duration <seconds>        (default: 300)
  --rate <calls_per_min>      (default: 60)
  --regions <csv>             (default: us-east-1,us-west-2)
  --verbose                   (show AWS output)

Examples (copy/paste):
  # Quick sanity test (prints output, exits fast)
  bash scripts/generate_activity.sh --scenario baseline --duration 10 --verbose

  # Real runs
  bash scripts/generate_activity.sh --scenario burst_api_calls --duration 120 --rate 180
  bash scripts/generate_activity.sh --scenario new_region --duration 180 --regions "us-east-1,eu-west-1,ap-southeast-1"
  bash scripts/generate_activity.sh --scenario access_denied_spike --duration 120 --rate 90
  bash scripts/generate_activity.sh --scenario mixed --duration 300
EOF
}

die() {
  echo "ERROR: $*" >&2
  echo "" >&2
  usage >&2
  exit 2
}

log() {
  # Always prints to terminal AND writes to log file (no "silent freeze").
  local msg="$1"
  local line="[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] $msg"
  echo "$line"
  echo "$line" >> "$LOG_FILE"
}

awsq() {
  # AWS wrapper: quiet by default, verbose if --verbose passed.
  if [[ "$QUIET" -eq 1 ]]; then
    aws "$@" >/dev/null 2>&1 || return $?
  else
    aws "$@" 2>&1 | tee -a "$LOG_FILE" || return $?
  fi
  return 0
}

calc_sleep() {
  local rate="$1"
  if [[ "$rate" -le 0 ]]; then
    echo "0"
  else
    # integer sleep; keep simple
    echo $(( 60 / rate ))
  fi
}

split_regions() {
  IFS=',' read -r -a REGION_ARR <<< "$REGIONS"
}

check_creds() {
  # Fails fast if creds not available (instead of "hanging")
  log "Checking AWS credentials..."
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    die "AWS credentials not working in this terminal. Assume the role (or set AWS_PROFILE) then rerun.
Try:
  aws sts get-caller-identity
"
  fi
}

write_expected_incident() {
  mkdir -p ./out
  local scenario="$1"
  local expected="$2"
  local severity="$3"
  echo "{\"ts\":\"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\",\"scenario\":\"$scenario\",\"expected\":\"$expected\",\"severity\":\"$severity\"}" \
    >> ./out/expected_incidents.jsonl
}

# -----------------------------
# Scenarios
# -----------------------------
scenario_baseline() {
  log "Scenario: baseline (safe/noisy read calls + light S3 list)"
  write_expected_incident "baseline" "none" "low"

  local end=$(( $(date +%s) + DURATION ))
  local sleep_s
  sleep_s="$(calc_sleep "$RATE")"

  while [[ $(date +%s) -lt "$end" ]]; do
    log "tick: baseline"
    awsq sts get-caller-identity || true
    awsq ec2 describe-instances --region us-east-1 || true
    awsq iam get-account-summary || true
    awsq iam list-roles --max-items 25 || true
    awsq s3api get-bucket-location --bucket "$LOG_BUCKET" || true
    awsq s3api list-objects-v2 --bucket "$LOG_BUCKET" --max-keys 5 || true
    [[ "$sleep_s" -gt 0 ]] && sleep "$sleep_s"
  done
}

scenario_burst_api_calls() {
  log "Scenario: burst_api_calls (rate spike via Describe* loops)"
  write_expected_incident "burst_api_calls" "rate_anomaly" "medium"

  local end=$(( $(date +%s) + DURATION ))
  local sleep_s
  sleep_s="$(calc_sleep "$RATE")"
  [[ "$sleep_s" -lt 0 ]] && sleep_s=0

  while [[ $(date +%s) -lt "$end" ]]; do
    log "tick: burst_api_calls"
    awsq ec2 describe-instances --region us-east-1 || true
    awsq ec2 describe-security-groups --region us-east-1 || true
    awsq ec2 describe-vpcs --region us-east-1 || true
    [[ "$sleep_s" -gt 0 ]] && sleep "$sleep_s"
  done
}

scenario_new_region() {
  log "Scenario: new_region (same calls across multiple regions quickly)"
  write_expected_incident "new_region" "new_region_anomaly" "high"

  split_regions
  local end=$(( $(date +%s) + DURATION ))
  local idx=0
  local n="${#REGION_ARR[@]}"

  while [[ $(date +%s) -lt "$end" ]]; do
    local r="${REGION_ARR[$idx]}"
    log "tick: new_region -> $r"
    awsq ec2 describe-instances --region "$r" || true
    awsq ec2 describe-vpcs --region "$r" || true
    awsq ec2 describe-route-tables --region "$r" || true
    idx=$(( (idx + 1) % n ))
    sleep 1
  done
}

scenario_access_denied_spike() {
  log "Scenario: access_denied_spike (intentionally failing calls)"
  write_expected_incident "access_denied_spike" "accessdenied_spike" "high"

  local end=$(( $(date +%s) + DURATION ))
  local sleep_s
  sleep_s="$(calc_sleep "$RATE")"

  while [[ $(date +%s) -lt "$end" ]]; do
    log "tick: access_denied_spike"
    local uname="anomai-should-fail-$(date +%s)-$RANDOM"
    awsq iam create-user --user-name "$uname" || true
    awsq ec2 run-instances --image-id ami-00000000000000000 --count 1 --instance-type t2.micro --region us-east-1 || true
    [[ "$sleep_s" -gt 0 ]] && sleep "$sleep_s"
  done
}

scenario_mixed() {
  log "Scenario: mixed (baseline -> burst -> new_region -> denied)"
  local total="$DURATION"
  DURATION=$(( total / 4 )); scenario_baseline
  DURATION=$(( total / 4 )); scenario_burst_api_calls
  DURATION=$(( total / 4 )); scenario_new_region
  DURATION=$(( total - 3*(total/4) )); scenario_access_denied_spike
}

# -----------------------------
# Parse args
# -----------------------------
if [[ $# -eq 0 ]]; then
  die "You must pass arguments. This script will not run with defaults."
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario) SCENARIO="${2:-}"; shift 2;;
    --duration) DURATION="${2:-}"; shift 2;;
    --rate) RATE="${2:-}"; shift 2;;
    --regions) REGIONS="${2:-}"; shift 2;;
    --verbose) QUIET=0; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown arg: $1";;
  esac
done

[[ -z "$SCENARIO" ]] && die "Missing required --scenario."

# Validate scenario
case "$SCENARIO" in
  baseline|burst_api_calls|new_region|access_denied_spike|mixed) ;;
  *) die "Invalid --scenario: $SCENARIO";;
esac

# -----------------------------
# Run
# -----------------------------
mkdir -p "$LOG_DIR"
LOG_FILE="${LOG_DIR}/activity_$(date -u +"%Y%m%d_%H%M%S")_${SCENARIO}.log"

log "Starting generate_activity.sh"
log "scenario=$SCENARIO duration=${DURATION}s rate=${RATE}/min regions=$REGIONS bucket=$LOG_BUCKET"
log "log_file=$LOG_FILE"

check_creds

case "$SCENARIO" in
  baseline) scenario_baseline;;
  burst_api_calls) scenario_burst_api_calls;;
  new_region) scenario_new_region;;
  access_denied_spike) scenario_access_denied_spike;;
  mixed) scenario_mixed;;
esac

log "Done."
echo "Log: $LOG_FILE"
echo "Expected incidents (optional): ./out/expected_incidents.jsonl"
