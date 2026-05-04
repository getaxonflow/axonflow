#!/usr/bin/env bash
# Runtime E2E test for W1 tenant durability.
#
# What this asserts:
#   A community-saas tenant registered before an agent-container restart
#   continues to authenticate successfully after the restart, because the
#   tenant row lives in Postgres (which persists across agent-container
#   restarts in the standard docker-compose deployment).
#
# Why this is a runtime test, not a unit test:
#   The Phase-0 investigation of the 2026-04-29 auth-failure cluster
#   identified the failure mode as cross-stack continuity (tenant rows
#   don't migrate when CFN stacks rotate). The W3 email-recovery PR
#   addressed the recovery path. W1 is the standing smoke test that
#   the BASE case — single stack, agent restart, same DB — works.
#
# Out of scope (deferred):
#   - Cross-stack tenant migration (different concern; W4 / future)
#   - Postgres failover (DB-tier resilience; not a tenant concern)
#   - Plugin-side credential persistence across machine reboots
#
# PREREQ: a running community-saas docker stack with a persistent
# postgres volume:
#   docker compose -f docker-compose.yml -f docker-compose.community-saas.yml up -d
#
# Run:
#   bash runtime-e2e/tenant_durability/test.sh
#
# Expected exit code: 0 on pass, non-zero on any failed assertion.

set -euo pipefail

AGENT_URL="${AGENT_URL:-http://localhost:8080}"
JQ="${JQ:-jq}"
AGENT_CONTAINER="${AGENT_CONTAINER:-axonflow-agent}"
DOCKER="${DOCKER:-docker}"
TEST_EMAIL="${TEST_EMAIL:-w1-durability-test-$$-$(date +%s)@axonflow-test.invalid}"

echo "=== W1 runtime-e2e: tenant durability across agent restart ==="
echo "Agent URL:     $AGENT_URL"
echo "Container:     $AGENT_CONTAINER"
echo "Test email:    $TEST_EMAIL"
echo ""

# -----------------------------------------------------------------------------
# Step 1: register a fresh tenant with email binding
# -----------------------------------------------------------------------------
echo "Step 1: register a fresh tenant"
REGISTER_RESP=$(curl -fsS -X POST "$AGENT_URL/api/v1/register" \
  -H "Content-Type: application/json" \
  -d "{\"label\":\"w1-durability-test\",\"email\":\"$TEST_EMAIL\"}")
TENANT_ID=$(echo "$REGISTER_RESP" | $JQ -r '.tenant_id')
SECRET=$(echo "$REGISTER_RESP" | $JQ -r '.secret')
if [ -z "$TENANT_ID" ] || [ "$TENANT_ID" == "null" ]; then
    echo "  ✗ FAIL: registration did not return tenant_id"
    echo "    response: $REGISTER_RESP"
    exit 1
fi
if [ -z "$SECRET" ] || [ "$SECRET" == "null" ]; then
    echo "  ✗ FAIL: registration did not return secret"
    exit 1
fi
echo "  ✓ PASS: tenant_id=$TENANT_ID"

# -----------------------------------------------------------------------------
# Step 2: confirm the credentials work BEFORE the restart (baseline assertion)
# -----------------------------------------------------------------------------
echo ""
echo "Step 2: pre-restart auth — credentials must work against current container"
PRE_AUTH_RESP=$(curl -fsS -u "$TENANT_ID:$SECRET" \
  -X POST "$AGENT_URL/api/v1/governance/explain" \
  -H "Content-Type: application/json" \
  -d '{"context":{"endpoint":"/test"},"action":"read"}' \
  -o /dev/null -w "%{http_code}" 2>&1) || PRE_AUTH_RESP="curl-failed"

# Any 2xx OR 4xx-not-401 confirms auth succeeded. 401 means auth failed
# (which we'd see if registration didn't actually persist before we read
# back). 5xx means server error, not auth — also acceptable as a signal
# the request reached past auth.
case "$PRE_AUTH_RESP" in
    2*|400|403|404|405|409|422|500|502|503)
        echo "  ✓ PASS: pre-restart request reached past auth (HTTP $PRE_AUTH_RESP)"
        ;;
    401)
        echo "  ✗ FAIL: pre-restart request returned 401 — credentials never worked"
        exit 1
        ;;
    *)
        echo "  ✗ FAIL: unexpected response $PRE_AUTH_RESP (curl error?)"
        exit 1
        ;;
esac

# -----------------------------------------------------------------------------
# Step 3: restart ONLY the agent container (DB volume must persist)
# -----------------------------------------------------------------------------
echo ""
echo "Step 3: restart the agent container ($AGENT_CONTAINER)"
if ! $DOCKER ps --format '{{.Names}}' | grep -q "^$AGENT_CONTAINER$"; then
    echo "  ✗ FAIL: container '$AGENT_CONTAINER' not running"
    echo "    Available containers:"
    $DOCKER ps --format '  {{.Names}}'
    echo "    Set AGENT_CONTAINER env var if your container has a different name."
    exit 1
fi
$DOCKER restart "$AGENT_CONTAINER" >/dev/null
echo "  ✓ PASS: docker restart issued"

# Wait for the agent to be reachable again. Use /health (no auth required).
echo "  ... waiting for $AGENT_URL/health to respond (max 30s)"
deadline=$(( $(date +%s) + 30 ))
ok=false
while [ "$(date +%s)" -lt "$deadline" ]; do
    if curl -fsS "$AGENT_URL/health" -o /dev/null --max-time 2 2>/dev/null; then
        ok=true
        break
    fi
    sleep 1
done
if [ "$ok" != "true" ]; then
    echo "  ✗ FAIL: agent did not become healthy within 30s after restart"
    exit 1
fi
echo "  ✓ PASS: agent is back online"

# -----------------------------------------------------------------------------
# Step 4: re-authenticate with the SAME credentials — must succeed because
# the tenant row lives in Postgres, not in agent process memory
# -----------------------------------------------------------------------------
echo ""
echo "Step 4: post-restart auth — same credentials must still work"
POST_AUTH_RESP=$(curl -fsS -u "$TENANT_ID:$SECRET" \
  -X POST "$AGENT_URL/api/v1/governance/explain" \
  -H "Content-Type: application/json" \
  -d '{"context":{"endpoint":"/test"},"action":"read"}' \
  -o /dev/null -w "%{http_code}" 2>&1) || POST_AUTH_RESP="curl-failed"

case "$POST_AUTH_RESP" in
    2*|400|403|404|405|409|422|500|502|503)
        echo "  ✓ PASS: post-restart request reached past auth (HTTP $POST_AUTH_RESP)"
        ;;
    401)
        echo "  ✗ FAIL: post-restart request returned 401 — tenant row was lost"
        echo "    This is a tenant-durability regression. Check:"
        echo "      - Postgres volume is persistent (docker volume inspect ...)"
        echo "      - Migrations ran on container restart (would they re-init the table?)"
        echo "      - The Postgres connection string survives the restart"
        exit 1
        ;;
    *)
        echo "  ✗ FAIL: unexpected post-restart response $POST_AUTH_RESP"
        exit 1
        ;;
esac

# -----------------------------------------------------------------------------
# Step 5: verify a NEW request also works (rules out single-call coincidence)
# -----------------------------------------------------------------------------
echo ""
echo "Step 5: second post-restart request — to rule out one-shot caching artifacts"
SECOND_RESP=$(curl -fsS -u "$TENANT_ID:$SECRET" \
  -X POST "$AGENT_URL/api/v1/governance/explain" \
  -H "Content-Type: application/json" \
  -d '{"context":{"endpoint":"/test2"},"action":"write"}' \
  -o /dev/null -w "%{http_code}" 2>&1) || SECOND_RESP="curl-failed"

case "$SECOND_RESP" in
    2*|400|403|404|405|409|422|500|502|503)
        echo "  ✓ PASS: second request also reached past auth (HTTP $SECOND_RESP)"
        ;;
    401)
        echo "  ✗ FAIL: second request returned 401 — tenant lookup not stable"
        exit 1
        ;;
    *)
        echo "  ✗ FAIL: unexpected response $SECOND_RESP"
        exit 1
        ;;
esac

echo ""
echo "=== W1 tenant durability runtime test PASSED ==="
echo "  tenant_id=$TENANT_ID survived agent container restart."
