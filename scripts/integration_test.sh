#!/usr/bin/env bash
# End-to-end integration test: generate a CloudTrail event, then wait for
# trailtool to show a session whose end_time is at or after the trigger.
#
# Usage:
#   AWS_PROFILE=sandbox-admin AWS_REGION=us-east-1 ./scripts/integration_test.sh
#
# Requirements: aws CLI, trailtool binary (or go run), jq

set -euo pipefail

TRAILTOOL="${TRAILTOOL:-go run ./cmd/trailtool/}"
POLL_INTERVAL=60   # seconds between checks
MAX_WAIT=900       # 15 minutes total
STEP=0

log() { echo "[$(date -u +%H:%M:%SZ)] $*"; }
fail() { log "FAIL: $*"; exit 1; }

# ── 1. Record trigger time ────────────────────────────────────────────────────
TRIGGER_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
log "Trigger time: $TRIGGER_TIME"

# ── 2. Generate a CloudTrail event via iam:ListRoles ─────────────────────────
# sts:GetCallerIdentity records lack sessionContext in CloudTrail, so the
# ingestor skips them (no roleARN). iam:ListRoles includes full session context.
log "Generating CloudTrail event (iam:ListRoles)..."
IDENTITY=$(aws sts get-caller-identity --output json)
ACCOUNT=$(echo "$IDENTITY" | jq -r '.Account')
USER_ARN=$(echo "$IDENTITY" | jq -r '.Arn')
aws iam list-roles --max-items 1 > /dev/null
log "Caller: $USER_ARN (account $ACCOUNT)"

# ── 3. Poll until trailtool shows a session at or after trigger time ──────────
log "Polling for new session (up to ${MAX_WAIT}s, every ${POLL_INTERVAL}s)..."

while true; do
    ELAPSED=$((STEP * POLL_INTERVAL))
    if (( ELAPSED >= MAX_WAIT )); then
        fail "Timed out after ${MAX_WAIT}s — no session with end_time >= $TRIGGER_TIME found"
    fi

    if (( STEP > 0 )); then
        log "Waiting ${POLL_INTERVAL}s before next check..."
        sleep "$POLL_INTERVAL"
    fi
    STEP=$(( STEP + 1 ))

    log "Check #${STEP} (${ELAPSED}s elapsed)..."

    # List sessions from the last day in JSON, find any whose end_time >= TRIGGER_TIME.
    # We check end_time (not start_time) because the trigger event is typically merged
    # into a pre-existing session — the ingestor groups events by role+time window.
    SESSIONS=$(${TRAILTOOL} sessions list --days 1 --format json 2>/dev/null) || {
        log "  trailtool returned non-zero, retrying..."
        continue
    }

    MATCH=$(echo "$SESSIONS" | jq -r \
        --arg t "$TRIGGER_TIME" \
        '(if type == "array" then . else [] end) | [.[] | select(.end_time >= $t)] | first | .start_time // empty')

    if [[ -n "$MATCH" ]]; then
        log "OK: Found session (start=$MATCH) with end_time >= trigger $TRIGGER_TIME"

        # Print detail for the matched session
        log "Session detail:"
        ${TRAILTOOL} sessions detail --at "${MATCH:0:19}" 2>/dev/null || true
        exit 0
    fi

    log "  No session with end_time >= $TRIGGER_TIME yet"
done
