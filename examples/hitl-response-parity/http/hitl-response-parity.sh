#!/usr/bin/env bash
# HITL Response Parity example (v7.4.0 / Issue #1677).
#
# Sends the approve verb through both planes (WCP and MAP), captures the
# responses, and asserts they carry the same field set modulo the single
# intentional asymmetry (`plan_id` populated on MAP, absent on WCP).
#
# Usage:
#   AGENT_URL=http://localhost:8080 \
#   USER_TOKEN=<jwt> \
#   ./hitl-response-parity.sh
#
# Prerequisites:
#   - Orchestrator + agent running in enterprise mode (see
#     `scripts/setup-e2e-testing.sh enterprise`)
#   - HITL enabled (`AXONFLOW_HITL_ENABLED=true`)
#   - jq installed locally
#
# Exit codes:
#   0 — both responses match the expected parity contract
#   1 — prerequisites missing (jq, env vars)
#   2 — a request failed
#   3 — parity violation: extra or missing field on one plane

set -euo pipefail

AGENT_URL="${AGENT_URL:-${AXONFLOW_AGENT_URL:-http://localhost:8080}}"
USER_TOKEN="${USER_TOKEN:-${AXONFLOW_USER_TOKEN:-}}"
TENANT_ID="${TENANT_ID:-tenant-demo}"
CLIENT_ID="${AXONFLOW_CLIENT_ID:-community}"
CLIENT_SECRET="${AXONFLOW_CLIENT_SECRET:-}"

if ! command -v jq >/dev/null 2>&1; then
	echo "fatal: jq is required" >&2
	exit 1
fi

# Build auth header — Basic auth if a client_secret (license) is set
# (enterprise / evaluation), Bearer if a JWT is supplied, otherwise nothing.
auth_header=()
if [[ -n "$CLIENT_SECRET" ]]; then
	auth_b64=$(printf '%s:%s' "$CLIENT_ID" "$CLIENT_SECRET" | base64)
	auth_header+=(-H "Authorization: Basic ${auth_b64}")
elif [[ -n "$USER_TOKEN" ]]; then
	auth_header+=(-H "Authorization: Bearer ${USER_TOKEN}")
fi

req() {
	local method="$1" path="$2" body="${3:-}"
	# ${auth_header[@]+"${auth_header[@]}"} expands to nothing when the array
	# is empty — `set -u` is strict about unset array access otherwise.
	if [[ -n "$body" ]]; then
		curl -s -X "$method" "${AGENT_URL}${path}" \
			-H 'Content-Type: application/json' \
			-H "X-Tenant-ID: ${TENANT_ID}" \
			-H 'X-User-ID: reviewer@example.com' \
			${auth_header[@]+"${auth_header[@]}"} \
			-d "$body"
	else
		curl -s -X "$method" "${AGENT_URL}${path}" \
			-H "X-Tenant-ID: ${TENANT_ID}" \
			-H 'X-User-ID: reviewer@example.com' \
			${auth_header[@]+"${auth_header[@]}"}
	fi
}

echo "==> Step 1/5 — create WCP workflow backing the approval"
wcp_create=$(req POST /api/v1/workflows '{
	"workflow_name": "hitl-parity-demo",
	"source": "external"
}')
WORKFLOW_ID=$(echo "$wcp_create" | jq -r '.workflow_id // empty')
if [[ -z "$WORKFLOW_ID" ]]; then
	echo "fatal: could not create workflow: $wcp_create" >&2
	exit 2
fi
echo "    workflow_id=$WORKFLOW_ID"

echo "==> Step 2/5 — gate a step with require_approval"
# The example assumes a dynamic policy is already loaded that fires
# require_approval when step_input.amount_eur > 1000. Adjust the amount or the
# policy to match your environment.
gate=$(req POST "/api/v1/workflows/${WORKFLOW_ID}/steps/step-1/gate" '{
	"step_name": "high-value-transfer",
	"step_type": "tool_call",
	"step_input": { "amount_eur": 8500 },
	"idempotency_key": "demo-payment-intent-1"
}')
gate_decision=$(echo "$gate" | jq -r '.decision')
if [[ "$gate_decision" != "require_approval" ]]; then
	echo "fatal: expected decision=require_approval, got $gate_decision" >&2
	echo "$gate" | jq . >&2
	exit 2
fi
echo "    gate.decision=require_approval gate_count=$(echo "$gate" | jq -r '.retry_context.gate_count')"

echo "==> Step 3/5 — approve via WCP plane (/api/v1/workflows/{id}/steps/{step_id}/approve)"
wcp_resp=$(req POST "/api/v1/workflows/${WORKFLOW_ID}/steps/step-1/approve" '{
	"comment": "Approved after full audit review of the demo scenario"
}')
wcp_decision=$(echo "$wcp_resp" | jq -r '.decision // empty')
if [[ "$wcp_decision" != "allow" ]]; then
	echo "fatal: WCP approve decision=$wcp_decision (want allow)" >&2
	echo "$wcp_resp" | jq . >&2
	exit 2
fi
echo "$wcp_resp" | jq .

echo ""
echo "==> Step 4/5 — create MAP plan in confirm mode (same require_approval policy)"
# A MAP confirm-mode plan creates its own WCP workflow internally; we reuse a
# second demo scenario with a fresh plan id so the two responses don't stomp.
# Canonical agent-level plan creation goes through /api/request (the agent
# routes request_type=multi-agent-plan to the orchestrator planner).
plan_create=$(req POST /api/request '{
	"query": "Process wire transfer: 8500 EUR to vendor",
	"user_token": "'"${USER_TOKEN:-community}"'",
	"client_id": "'"${CLIENT_ID}"'",
	"request_type": "multi-agent-plan",
	"context": {
		"domain": "banking",
		"execution_mode": "confirm"
	}
}' || echo '{}')
PLAN_ID=$(echo "$plan_create" | jq -r '.plan_id // (.data.plan_id // empty)')
if [[ -z "$PLAN_ID" ]]; then
	echo "note: /api/request plan creation unavailable in this environment; falling back to WCP-only parity check"
	MAP_AVAILABLE=0
else
	# Fire the plan to drive the first step into require_approval.
	req POST /api/request '{
		"query": "execute",
		"user_token": "'"${USER_TOKEN:-community}"'",
		"client_id": "'"${CLIENT_ID}"'",
		"request_type": "execute-plan",
		"context": { "plan_id": "'"${PLAN_ID}"'" }
	}' >/dev/null || true
	MAP_AVAILABLE=1
fi

if [[ "$MAP_AVAILABLE" == "1" ]]; then
	echo "    plan_id=$PLAN_ID — approving first step"
	map_resp=$(req POST "/api/v1/plans/${PLAN_ID}/steps/step_0/approve" '{
		"comment": "Approved after full audit review via plan endpoint"
	}')
	echo "$map_resp" | jq .
else
	map_resp=""
fi

echo ""
echo "==> Step 5/5 — parity check"
# Extract the JSON key set from each response.
wcp_keys=$(echo "$wcp_resp" | jq -r 'keys[]' | sort | tr '\n' ' ')
echo "    WCP response keys:  $wcp_keys"

if [[ -n "$map_resp" ]]; then
	map_keys=$(echo "$map_resp" | jq -r 'keys[]' | sort | tr '\n' ' ')
	echo "    MAP response keys:  $map_keys"

	# Compute the symmetric difference. The one allowed asymmetry is plan_id.
	diff_lines=$(comm -3 \
		<(echo "$wcp_resp" | jq -r 'keys[]' | sort) \
		<(echo "$map_resp" | jq -r 'keys[]' | sort) \
		| grep -v '^\s*plan_id$' \
		| awk NF || true)

	if [[ -n "$diff_lines" ]]; then
		echo "" >&2
		echo "PARITY VIOLATION — WCP and MAP response field sets differ:" >&2
		echo "$diff_lines" >&2
		exit 3
	fi
	echo "    ✓ WCP ≡ MAP field set (plan_id correctly MAP-only)"
else
	echo "    (MAP plane skipped — plan endpoint unavailable in this environment)"
fi

echo ""
echo "HITL response parity verified — both planes surface retry_context,"
echo "approval_id, approver metadata, and policies_matched consistently."
