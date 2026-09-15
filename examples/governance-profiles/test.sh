#!/usr/bin/env bash
# AxonFlow v11: removed governance profiles -> organization overrides
#
# AXONFLOW_PROFILE and AXONFLOW_ENFORCE were removed in v11; no environment
# variable sets a detection action. This script records the organization
# overrides that correspond to a removed profile through the customer portal
# API (Enterprise), reads them back, and fails if they differ. See README.md
# for the mapping and what an override cannot reach (sensitive data).
#
# Usage: ./test.sh <dev|default|strict|compliance>
# Env:   AXONFLOW_PORTAL_URL      customer portal (default http://localhost:8082)
#        AXONFLOW_PORTAL_SESSION  axonflow_session cookie of a user with sso:configure

set -euo pipefail

PROFILE="${1:-}"
CATEGORIES=(pii sqli dangerous_command)

# Override action per category, in CATEGORIES order. "-" means no override:
# the stored policy action decides.
case "$PROFILE" in
    dev)               ACTIONS=(log log warn) ;;
    default)           ACTIONS=(- - -) ;;
    strict|compliance) ACTIONS=(block block block) ;;
    *)
        echo "Usage: $0 <dev|default|strict|compliance>" >&2
        exit 2
        ;;
esac

PORTAL_URL="${AXONFLOW_PORTAL_URL:-http://localhost:8082}"
SESSION="${AXONFLOW_PORTAL_SESSION:?set AXONFLOW_PORTAL_SESSION to a customer-portal session cookie (user needs sso:configure)}"

echo "=== Profile '${PROFILE}' as organization overrides (${PORTAL_URL}) ==="
EXPECTED=()
for i in "${!CATEGORIES[@]}"; do
    category="${CATEGORIES[$i]}"
    action="${ACTIONS[$i]}"
    if [ "$action" != "-" ]; then
        code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT \
            "${PORTAL_URL}/api/v1/detection-posture/${category}" \
            -H "Content-Type: application/json" \
            -b "axonflow_session=${SESSION}" \
            -d "{\"action\":\"${action}\"}")
        echo "  PUT ${category}=${action} -> ${code}"
        if [ "$code" != "200" ]; then
            echo "✗ PUT ${category} failed (HTTP ${code})" >&2
            exit 1
        fi
        EXPECTED+=("${category}=${action}")
    else
        code=$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE \
            "${PORTAL_URL}/api/v1/detection-posture/${category}" \
            -b "axonflow_session=${SESSION}")
        echo "  DELETE ${category} -> ${code}"
        if [ "$code" != "204" ]; then
            echo "✗ DELETE ${category} failed (HTTP ${code})" >&2
            exit 1
        fi
    fi
done

body=$(curl -sS -f "${PORTAL_URL}/api/v1/detection-posture" -b "axonflow_session=${SESSION}")

echo "Recorded overrides:"
if printf '%s' "$body" | python3 -c '
import json, sys
want = dict(arg.split("=", 1) for arg in sys.argv[1:])
cats = ("pii", "sqli", "dangerous_command")
got = {o["category"]: o["action"] for o in (json.load(sys.stdin).get("overrides") or []) if o.get("category") in cats}
for c in sorted(cats):
    print("  %s = %s" % (c, got.get(c, "(none: stored policy action decides)")))
sys.exit(0 if got == want else 1)
' ${EXPECTED[@]+"${EXPECTED[@]}"}; then
    echo "✓ Recorded overrides match profile '${PROFILE}'"
else
    echo "✗ Recorded overrides do not match profile '${PROFILE}'" >&2
    exit 1
fi
