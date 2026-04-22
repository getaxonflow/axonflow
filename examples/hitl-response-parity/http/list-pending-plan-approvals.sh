#!/usr/bin/env bash
# MAP plane-scoped pending approvals example (v7.4.0 / Issue #1680).
#
# Walks the reviewer lifecycle for a MAP-backed approval:
#   1. Creates a MAP plan in confirm mode that will hit require_approval
#      on its first step.
#   2. Lists the tenant's MAP-plane pending approvals and asserts the new
#      entry is visible with plan_id populated.
#   3. Also lists the WCP-plane pending approvals to confirm the same
#      approval shows up there (workflows/approvals/pending is a
#      plane-neutral view) but WITHOUT plan_id — the intentional asymmetry.
#   4. Exercises the ?plan_id= filter to scope the MAP listing to a
#      single plan.
#   5. Approves the step and re-lists both planes to confirm the entry
#      disappears from both views.
#
# Usage:
#   AGENT_URL=http://localhost:8080 \
#   AXONFLOW_CLIENT_ID=<id> AXONFLOW_CLIENT_SECRET=<secret> \
#   USER_TOKEN=<jwt> \
#   ./list-pending-plan-approvals.sh
#
# Prerequisites:
#   - Orchestrator + agent running at Evaluation or Enterprise tier
#     (./scripts/setup-e2e-testing.sh evaluation | enterprise)
#   - HITL enabled (`AXONFLOW_HITL_ENABLED=true`)
#   - A dynamic policy loaded that matches the demo step (see README).
#   - jq installed locally
#
# Exit codes:
#   0 — both plane listings behaved as expected
#   1 — prerequisites missing (jq, env vars)
#   2 — a request failed
#   3 — parity violation (plan_id leak into WCP listing, or missing from MAP)

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

# Build auth header pair — Basic auth if secret is set (enterprise / eval
# license), Authorization: Bearer if a JWT is supplied, otherwise nothing.
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

echo "==> Step 1/5 — create MAP plan in confirm mode (drives step into require_approval)"
# Canonical agent-level API for creating a MAP plan in confirm mode. Matches
# the pattern used by examples/map-confirm-mode/http/map-confirm.sh.
plan_create=$(req POST /api/request '{
	"query": "Process wire transfer: 8500 EUR to vendor",
	"user_token": "'"${USER_TOKEN:-community}"'",
	"client_id": "'"${CLIENT_ID}"'",
	"request_type": "multi-agent-plan",
	"context": {
		"domain": "banking",
		"execution_mode": "confirm"
	}
}')
PLAN_ID=$(echo "$plan_create" | jq -r '.plan_id // (.data.plan_id // empty)')
if [[ -z "$PLAN_ID" ]]; then
	echo "fatal: could not create MAP confirm plan. Check server is running with HITL enabled" >&2
	echo "$plan_create" | jq . >&2
	exit 2
fi
echo "    plan_id=$PLAN_ID"

# Execute the stored plan so its first step gets gated.
req POST /api/request '{
	"query": "execute",
	"user_token": "'"${USER_TOKEN:-community}"'",
	"client_id": "'"${CLIENT_ID}"'",
	"request_type": "execute-plan",
	"context": { "plan_id": "'"${PLAN_ID}"'" }
}' >/dev/null || true

echo ""
echo "==> Step 2/5 — list MAP-plane pending approvals (plan_id populated on every entry)"
map_list=$(req GET "/api/v1/plans/approvals/pending")
map_count=$(echo "$map_list" | jq -r '.count')
echo "$map_list" | jq .

if [[ "$map_count" -lt 1 ]]; then
	echo "fatal: expected at least one MAP-plane pending approval, got $map_count" >&2
	exit 2
fi

# Assert plan_id is populated on every MAP entry.
missing_plan=$(echo "$map_list" | jq -r '.pending_approvals[] | select(.plan_id == null or .plan_id == "") | .step_id' | awk NF || true)
if [[ -n "$missing_plan" ]]; then
	echo "PARITY VIOLATION — MAP entry missing plan_id: $missing_plan" >&2
	exit 3
fi
echo "    ✓ all MAP entries carry plan_id"

echo ""
echo "==> Step 3/5 — list WCP-plane pending approvals (plan_id must NOT appear)"
wcp_list=$(req GET "/api/v1/workflows/approvals/pending")
echo "$wcp_list" | jq .

# The same underlying approval should show up on the WCP listing (it's the
# plane-neutral queue over all tenants' approvals), but plan_id is the one
# field WCP never surfaces — the omitempty serializer drops it when empty.
wcp_leaked_plan=$(echo "$wcp_list" | jq -r '.pending_approvals[] | select(has("plan_id")) | .step_id' | awk NF || true)
if [[ -n "$wcp_leaked_plan" ]]; then
	echo "PARITY VIOLATION — WCP entry carried plan_id (should be omitted): $wcp_leaked_plan" >&2
	exit 3
fi
echo "    ✓ no WCP entry leaks plan_id"

echo ""
echo "==> Step 4/5 — ?plan_id= filter scopes the MAP listing to one plan"
filtered=$(req GET "/api/v1/plans/approvals/pending?plan_id=${PLAN_ID}")
filtered_count=$(echo "$filtered" | jq -r '.count')
echo "    plan_id=${PLAN_ID} → count=$filtered_count"

unfiltered_ids=$(echo "$filtered" | jq -r '.pending_approvals[] | select(.plan_id != "'"${PLAN_ID}"'") | .plan_id' | awk NF || true)
if [[ -n "$unfiltered_ids" ]]; then
	echo "fatal: filter leaked other plans: $unfiltered_ids" >&2
	exit 3
fi
echo "    ✓ filter correctly scoped to $PLAN_ID"

echo ""
echo "==> Step 5/5 — approve the step, re-list MAP plane, confirm entry disappears"
# Look up the actual step_id from the filtered listing — MAP auto-generates
# step ids that don't always follow step_0 / step_1 naming, so we can't
# hardcode one here.
STEP_ID=$(echo "$filtered" | jq -r '.pending_approvals[0].step_id')
if [[ -z "$STEP_ID" || "$STEP_ID" == "null" ]]; then
	echo "fatal: couldn't determine step_id to approve from filtered listing" >&2
	echo "$filtered" | jq . >&2
	exit 2
fi
echo "    approving plan=$PLAN_ID step=$STEP_ID"
approve_resp=$(req POST "/api/v1/plans/${PLAN_ID}/steps/${STEP_ID}/approve" '{
	"comment": "Approved after full audit review via plan endpoint"
}')
approve_decision=$(echo "$approve_resp" | jq -r '.decision // empty')
if [[ "$approve_decision" != "allow" ]]; then
	echo "fatal: approve decision=$approve_decision (want allow)" >&2
	echo "$approve_resp" | jq . >&2
	exit 2
fi

map_after=$(req GET "/api/v1/plans/approvals/pending?plan_id=${PLAN_ID}")
map_after_count=$(echo "$map_after" | jq -r '.count')
if [[ "$map_after_count" -ne 0 ]]; then
	echo "fatal: after approval, MAP listing still has $map_after_count entries for $PLAN_ID" >&2
	echo "$map_after" | jq . >&2
	exit 2
fi
echo "    ✓ MAP listing cleared for $PLAN_ID"

echo ""
echo "MAP plane-scoped pending approvals verified:"
echo "  • /api/v1/plans/approvals/pending returns plan_id on every entry"
echo "  • /api/v1/workflows/approvals/pending omits plan_id (WCP-plane asymmetry)"
echo "  • ?plan_id= filter scopes to a single plan"
echo "  • Approving the step removes it from the MAP listing"
