#!/usr/bin/env bash
# End-to-end integration test: assume a role with session tags + inline session policy,
# then wait for trailtool to surface the child session and verify:
#   1. `sessions list --tag` finds the session by tag
#   2. `sessions detail` shows the Session Tags block
#   3. `sessions detail` shows the Session Policy block
#
# Strategy: first confirm the AssumeRole event is visible in CloudTrail
# (LookupEvents on the issued access key), then do a short wait for ingestion.
# This avoids long blind polling when the ingestor simply hasn't fired yet.
#
# Usage:
#   AWS_PROFILE=sandbox-admin AWS_REGION=us-east-1 ./scripts/integration_test_session_tags.sh
#
# Requirements: aws CLI, trailtool binary (or go run), jq

set -euo pipefail

TRAILTOOL="${TRAILTOOL:-go run ./cmd/trailtool/}"
ROLE_ARN="${ROLE_ARN:-arn:aws:iam::278835131762:role/RoleChaining1}"

# Phase 1: wait for the AssumeRole event to appear in CloudTrail LookupEvents
CT_POLL_INTERVAL=15   # seconds between CloudTrail checks
CT_MAX_WAIT=300       # 5 minutes — if the event isn't in CT by then, something is wrong

# Phase 2: wait for trailtool to ingest the event and surface the session
TT_POLL_INTERVAL=60   # seconds between trailtool checks
TT_MAX_WAIT=600       # 10 minutes — ingestor fires on S3 delivery (~5 min typical)

log()  { echo "[$(date -u +%H:%M:%SZ)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

SESSION_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"iam:ListRoles","Resource":"*"}]}'
TAG_AGENT="claude-code"
TAG_TASK="integration-test-$$"

# ── 1. Record trigger time ────────────────────────────────────────────────────
TRIGGER_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log "Trigger time: $TRIGGER_TIME"
log "Role ARN: $ROLE_ARN"
log "Tags: AgentName=$TAG_AGENT, Task=$TAG_TASK"

# ── 2. AssumeRole with session tags and inline session policy ─────────────────
log "Assuming role with session tags and session policy..."
CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name "trailtool-inttest-$$" \
  --tags "[{\"Key\":\"AgentName\",\"Value\":\"$TAG_AGENT\"},{\"Key\":\"Task\",\"Value\":\"$TAG_TASK\"}]" \
  --policy "$SESSION_POLICY" \
  --output json)

CHILD_KEY=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
CHILD_SECRET=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
CHILD_TOKEN=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')
log "Issued key: $CHILD_KEY"

# ── 3. Make an API call using the child credentials to generate a CloudTrail event ──
# iam:ListRoles includes full sessionContext in CloudTrail, which the ingestor needs
# to attribute the session (sts:GetCallerIdentity events lack sessionContext).
log "Making API call with child credentials (iam:ListRoles)..."
AWS_ACCESS_KEY_ID="$CHILD_KEY" \
AWS_SECRET_ACCESS_KEY="$CHILD_SECRET" \
AWS_SESSION_TOKEN="$CHILD_TOKEN" \
  aws iam list-roles --max-items 1 > /dev/null
log "CloudTrail event generated"

# ── 4. Poll CloudTrail LookupEvents until AssumeRole event is visible ─────────
# This confirms our event made it into CloudTrail before we wait for ingestion.
# LookupEvents on AccessKeyId finds events where the key was *issued*, not used.
# We use the username (session name) instead, which appears as the principalId.
SESSION_NAME="trailtool-inttest-$$"
log "Waiting for AssumeRole event to appear in CloudTrail LookupEvents (up to ${CT_MAX_WAIT}s)..."
CT_STEP=0
CT_FOUND=false
while true; do
    CT_ELAPSED=$((CT_STEP * CT_POLL_INTERVAL))
    if (( CT_ELAPSED >= CT_MAX_WAIT )); then
        fail "AssumeRole event not visible in CloudTrail after ${CT_MAX_WAIT}s — ingestor will not pick it up"
    fi

    if (( CT_STEP > 0 )); then
        sleep "$CT_POLL_INTERVAL"
    fi
    CT_STEP=$(( CT_STEP + 1 ))
    log "CloudTrail check #${CT_STEP} (${CT_ELAPSED}s elapsed)..."

    # Look up AssumeRole events after trigger time, find ours by the issued key ID
    CT_RESULT=$(aws cloudtrail lookup-events \
        --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
        --start-time "$TRIGGER_TIME" \
        --output json 2>/dev/null) || continue

    FOUND_KEY=$(echo "$CT_RESULT" | jq -r \
        --arg key "$CHILD_KEY" \
        '.Events[]?.CloudTrailEvent | fromjson? |
         select(.responseElements.credentials.accessKeyId == $key) |
         .responseElements.credentials.accessKeyId // empty' | head -1)

    if [[ -n "$FOUND_KEY" ]]; then
        log "OK: AssumeRole event confirmed in CloudTrail (issued key $FOUND_KEY)"
        CT_FOUND=true
        break
    fi
    log "  Not visible yet..."
done

# ── 5. Poll trailtool until the child session is ingested ─────────────────────
log "Polling trailtool for child session with tag AgentName=$TAG_AGENT (up to ${TT_MAX_WAIT}s)..."
TT_STEP=0
MATCH_START=""
while true; do
    TT_ELAPSED=$((TT_STEP * TT_POLL_INTERVAL))
    if (( TT_ELAPSED >= TT_MAX_WAIT )); then
        log ""
        log "NOTE: AssumeRole event IS confirmed in CloudTrail (key $CHILD_KEY)."
        log "  If the session_tags/session_policy fields are missing from DynamoDB, the"
        log "  ingestor Lambda needs to be redeployed with the current code."
        fail "Timed out after ${TT_MAX_WAIT}s — event in CloudTrail but session not found by trailtool --tag filter"
    fi

    if (( TT_STEP > 0 )); then
        log "Waiting ${TT_POLL_INTERVAL}s before next check..."
        sleep "$TT_POLL_INTERVAL"
    fi
    TT_STEP=$(( TT_STEP + 1 ))
    log "trailtool check #${TT_STEP} (${TT_ELAPSED}s elapsed)..."

    SESSIONS=$(${TRAILTOOL} sessions list --days 1 --tag "AgentName=$TAG_AGENT" --format json 2>/dev/null) || {
        log "  trailtool returned non-zero, retrying..."
        continue
    }

    MATCH_START=$(echo "$SESSIONS" | jq -r \
        --arg t "$TRIGGER_TIME" \
        '(if type == "array" then . else [] end) | [.[] | select(.end_time >= $t)] | first | .start_time // empty')

    if [[ -n "$MATCH_START" ]]; then
        log "OK: Found session (start=$MATCH_START) with end_time >= trigger $TRIGGER_TIME"
        break
    fi
    log "  No matching session yet"
done

# ── 6. Fetch detail and verify session tags + session policy appear ────────────
log "Fetching session detail..."
DETAIL=$(${TRAILTOOL} sessions detail --at "${MATCH_START:0:19}" 2>/dev/null)
echo "$DETAIL"

if echo "$DETAIL" | grep -q "AgentName"; then
    log "OK: Session Tags block present (AgentName found)"
else
    fail "Session Tags block missing from sessions detail output"
fi

if echo "$DETAIL" | grep -q "Task"; then
    log "OK: Session Tags block contains Task tag"
else
    fail "Task tag missing from sessions detail output"
fi

if echo "$DETAIL" | grep -q "Session Policy"; then
    log "OK: Session Policy block present"
else
    fail "Session Policy block missing from sessions detail output"
fi

if echo "$DETAIL" | grep -q "iam:ListRoles"; then
    log "OK: Session Policy content correct (iam:ListRoles found)"
else
    fail "Session Policy content incorrect — iam:ListRoles not found in output"
fi

log "ALL CHECKS PASSED"
