#!/usr/bin/env bash
# Build the keygen utility, fetch Ed25519 signing keys from AWS Secrets
# Manager, generate a tier-appropriate license, and emit license_key /
# org_id / client_id / user_token as $GITHUB_OUTPUT lines.
#
# Usage:
#   ./tests/tier-gate/setup_license.sh evaluation
#   ./tests/tier-gate/setup_license.sh enterprise
#
# Required environment:
#   AWS credentials configured (so aws secretsmanager get-secret-value works)
#   - OR -
#   AXONFLOW_EVAL_SIGNING_KEY / AXONFLOW_ENT_SIGNING_KEY exported directly
#
# Outputs (stdout, GitHub Actions $GITHUB_OUTPUT format):
#   license_key=<base64 license>
#   org_id=<UUID>
#   client_id=<same as org_id for the runner>
#   user_token=<JWT for tier-gate test tenant>

set -euo pipefail

MODE="${1:-}"
case "${MODE}" in
    evaluation|enterprise) ;;
    *)
        echo "ERROR: mode must be 'evaluation' or 'enterprise', got: '${MODE}'" >&2
        exit 2
        ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYGEN_DIR="${REPO_ROOT}/ee/platform/agent/license/cmd/keygen"
KEYGEN_BIN="$(mktemp -d)/keygen"
ORG_ID="${ORG_ID_OVERRIDE:-a1b2c3d4-e5f6-7890-abcd-ef1234567890}"
DAYS=7
JWT_SECRET="${JWT_SECRET:-axonflow-local-dev-jwt-secret-do-not-use-in-production}"

log() { echo "# $*" >&2; }

# ----------------------------------------------------------------------------
# Load signing keys: env var first, AWS Secrets Manager fallback.
# ----------------------------------------------------------------------------
load_signing_keys() {
    if [ -z "${AXONFLOW_EVAL_SIGNING_KEY:-}" ]; then
        log "Fetching Evaluation signing key from AWS Secrets Manager..."
        AXONFLOW_EVAL_SIGNING_KEY="$(aws secretsmanager get-secret-value \
            --secret-id axonflow/license-signing/evaluation-private-key \
            --region us-east-1 \
            --query SecretString --output text)"
        export AXONFLOW_EVAL_SIGNING_KEY
    fi
    if [ -z "${AXONFLOW_ENT_SIGNING_KEY:-}" ]; then
        log "Fetching Enterprise signing key from AWS Secrets Manager..."
        AXONFLOW_ENT_SIGNING_KEY="$(aws secretsmanager get-secret-value \
            --secret-id axonflow/license-signing/enterprise-private-key \
            --region us-east-1 \
            --query SecretString --output text)"
        export AXONFLOW_ENT_SIGNING_KEY
    fi
    if [ -z "${AXONFLOW_EVAL_SIGNING_KEY}" ] || [ -z "${AXONFLOW_ENT_SIGNING_KEY}" ]; then
        echo "ERROR: signing keys empty after load" >&2
        exit 1
    fi
}

# ----------------------------------------------------------------------------
# Build keygen utility (enterprise build tag required).
# ----------------------------------------------------------------------------
build_keygen() {
    log "Building keygen at ${KEYGEN_BIN}..."
    (cd "${KEYGEN_DIR}" && go build -tags enterprise -o "${KEYGEN_BIN}" .)
    chmod +x "${KEYGEN_BIN}"
}

# ----------------------------------------------------------------------------
# Generate license for the requested mode.
# ----------------------------------------------------------------------------
generate_license() {
    local tier perms
    if [ "${MODE}" = "evaluation" ]; then
        tier="Evaluation"
        perms="mcp:*:*,llm:*:*"
    else
        tier="Enterprise"
        perms="mcp:*:*,llm:*:*,policies:*:*,hitl:*:*,connectors:*:*,admin:*:*"
    fi

    log "Generating ${tier} license for org=${ORG_ID} days=${DAYS}..."
    LICENSE_KEY="$("${KEYGEN_BIN}" \
        -tier "${tier}" \
        -org "${ORG_ID}" \
        -days "${DAYS}" \
        -permissions "${perms}" \
        -quiet)"

    if [ -z "${LICENSE_KEY}" ]; then
        echo "ERROR: keygen produced empty license" >&2
        exit 1
    fi
    log "License generated (length=${#LICENSE_KEY})"
}

# ----------------------------------------------------------------------------
# Generate JWT user token whose tenant matches AXONFLOW_CLIENT_ID.
# ----------------------------------------------------------------------------
generate_user_token() {
    local tenant_id="${ORG_ID}"
    if [ ! -x "${REPO_ROOT}/scripts/generate-jwt.sh" ]; then
        echo "ERROR: ${REPO_ROOT}/scripts/generate-jwt.sh not executable" >&2
        exit 1
    fi
    log "Generating JWT for tenant_id=${tenant_id}..."
    USER_TOKEN="$("${REPO_ROOT}/scripts/generate-jwt.sh" \
        --user-id "tier-gate-runner" \
        --tenant-id "${tenant_id}" \
        --permissions "query,llm,mcp_query,admin" \
        --role "admin" \
        --secret "${JWT_SECRET}" \
        --quiet)"
    if [ -z "${USER_TOKEN}" ]; then
        echo "ERROR: JWT generation produced empty token" >&2
        exit 1
    fi
    log "JWT generated (length=${#USER_TOKEN})"
}

main() {
    load_signing_keys
    build_keygen
    generate_license
    generate_user_token

    # Emit GitHub-Actions $GITHUB_OUTPUT key=value lines.
    # client_secret = license_key in the agent's Basic-auth model
    # (setup-e2e-testing.sh:778 establishes this mapping).
    echo "license_key=${LICENSE_KEY}"
    echo "org_id=${ORG_ID}"
    echo "client_id=${ORG_ID}"
    echo "client_secret=${LICENSE_KEY}"
    echo "user_token=${USER_TOKEN}"
}

main "$@"
