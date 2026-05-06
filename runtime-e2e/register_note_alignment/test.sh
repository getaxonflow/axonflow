#!/usr/bin/env bash
# Runtime E2E test for the register-note alignment with pricing-page promises.
#
# This PR rewrites the customer-facing `note` field in the registration
# response to drop the "intended for basic testing and evaluation" framing
# (which contradicts pricing.html's "serious individual use" positioning of
# Plugin Pro). HARD RULE #0 (runtime proof is definition of done) requires
# we exercise the change against a live agent rather than rely on unit
# tests alone.
#
# What this test asserts against a live community-saas docker stack:
#   1. POST /api/v1/register returns 201 Created with a parseable JSON body
#   2. The response.note field contains the new operational facts:
#        - "3-day audit retention"
#        - "200 events/day"
#        - "3 months of inactivity"
#        - "1 year from creation"
#        - "Plugin Pro"
#        - "30-day retention"
#        - "1,000 events/day"
#        - "$9.99"
#        - "https://www.getaxonflow.com/pricing/"
#   3. The response.note field does NOT contain the old framing:
#        - "intended for basic testing and evaluation"
#        - "we recommend self-hosting AxonFlow from day one"
#        - "we cannot offer reliability or security guarantees"
#        - "by using it you accept these constraints"
#
# PREREQ: a community-saas-mode agent stack is running locally on
#         http://localhost:8080. Standard setup:
#           ./scripts/setup-e2e-testing.sh community
#         (per HARD RULE #4 in CLAUDE.md)

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
JQ="${JQ:-jq}"

EVIDENCE_DIR="${EVIDENCE_DIR:-runtime-e2e/register_note_alignment/EVIDENCE/$(date -u +%Y-%m-%dT%H%M%SZ)}"
mkdir -p "$EVIDENCE_DIR"

echo "=== runtime-e2e: register-note alignment with pricing-page promises ==="
echo "Agent URL: $AGENT_URL"
echo "Evidence dir: $EVIDENCE_DIR"
echo ""

# -----------------------------------------------------------------------------
# Step 1: register a fresh tenant
# -----------------------------------------------------------------------------
echo "Step 1: POST /api/v1/register"
register_resp="$EVIDENCE_DIR/register_response.json"
register_err="$EVIDENCE_DIR/register_err.txt"

http_code=$(curl -sS -o "$register_resp" -w '%{http_code}' \
    -X POST "$AGENT_URL/api/v1/register" \
    -H "Content-Type: application/json" \
    -d '{"label":"runtime-e2e:register-note-alignment"}' \
    2>"$register_err" || true)

if [[ "$http_code" != "201" ]]; then
    echo "  FAIL: expected 201, got $http_code"
    echo "  curl stderr:"
    cat "$register_err"
    echo "  body:"
    cat "$register_resp"
    exit 1
fi
echo "  OK: 201 with body $(wc -c < "$register_resp") bytes"

NOTE=$($JQ -r '.note' "$register_resp")
TENANT_ID=$($JQ -r '.tenant_id' "$register_resp")
if [[ -z "$NOTE" || "$NOTE" == "null" ]]; then
    echo "  FAIL: response.note is empty or null"
    cat "$register_resp"
    exit 1
fi
echo "  Tenant: $TENANT_ID"
echo ""

# -----------------------------------------------------------------------------
# Step 2: assert the new operational facts are present
# -----------------------------------------------------------------------------
echo "Step 2: assert new operational-fact substrings"
must_contain=(
    "3-day audit retention"
    "200 events/day"
    "3 months of inactivity"
    "1 year from creation"
    "Plugin Pro"
    "30-day retention"
    "1,000 events/day"
    "\$9.99"
    "https://www.getaxonflow.com/pricing/"
)
fail=0
for s in "${must_contain[@]}"; do
    if grep -qF "$s" <<<"$NOTE"; then
        echo "  OK:    note contains $s"
    else
        echo "  FAIL:  note missing $s"
        fail=1
    fi
done
echo ""

# -----------------------------------------------------------------------------
# Step 3: assert the OLD framing is gone
# -----------------------------------------------------------------------------
echo "Step 3: assert old framing is absent"
must_not_contain=(
    "intended for basic testing and evaluation"
    "we recommend self-hosting AxonFlow from day one"
    "we cannot offer reliability or security guarantees"
    "by using it you accept these constraints"
)
for s in "${must_not_contain[@]}"; do
    if grep -qF "$s" <<<"$NOTE"; then
        echo "  FAIL:  note contains stale phrase $s"
        fail=1
    else
        echo "  OK:    note does not contain $s"
    fi
done
echo ""

# -----------------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------------
if [[ "$fail" -ne 0 ]]; then
    echo "=== FAIL ==="
    echo "  See $register_resp for the actual note bytes."
    exit 1
fi

echo "=== PASS — register-note aligned with pricing-page promises ==="
echo "  Evidence: $EVIDENCE_DIR/"
