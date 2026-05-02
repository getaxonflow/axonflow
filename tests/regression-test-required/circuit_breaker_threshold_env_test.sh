#!/usr/bin/env bash
# Regression guard: AXONFLOW_CB_ERROR_THRESHOLD and
# AXONFLOW_CB_POLICY_VIOLATION_THRESHOLD must plumb end-to-end from
# workflow_dispatch input → CFN parameter → agent container env →
# platform/agent/run.go envIntDefault call.
#
# Without all wiring points, an operator passing the override at deploy
# time silently sees the breaker trip at the production-default thresholds
# (10 errors / 20 violations per 5-min window per client), which is the
# right default for production but pre-empts benchmark traffic after the
# first second of attack-pattern load.

set -euo pipefail

CFN_TEMPLATE="ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml"
DEPLOY_SCRIPT="scripts/deployment/deploy-cloudformation.sh"
DEPLOY_WORKFLOW=".github/workflows/deploy-platform.yml"
AGENT_RUN="platform/agent/run.go"

for f in "$CFN_TEMPLATE" "$DEPLOY_SCRIPT" "$DEPLOY_WORKFLOW" "$AGENT_RUN"; do
    if [ ! -f "$f" ]; then
        echo "❌ $f not found"
        exit 1
    fi
done

ROWS=(
    "CBErrorThreshold HasCBErrorThreshold AXONFLOW_CB_ERROR_THRESHOLD cb_error_threshold CB_ERROR_THRESHOLD_OVERRIDE cb_error_threshold"
    "CBPolicyViolationThreshold HasCBPolicyViolationThreshold AXONFLOW_CB_POLICY_VIOLATION_THRESHOLD cb_policy_violation_threshold CB_POLICY_VIOLATION_THRESHOLD_OVERRIDE cb_policy_violation_threshold"
)

FAILED=0

for row in "${ROWS[@]}"; do
    # shellcheck disable=SC2206
    parts=( $row )
    PARAM="${parts[0]}"
    COND="${parts[1]}"
    ENV_VAR="${parts[2]}"
    YAML_KEY="${parts[3]}"
    OVERRIDE_VAR="${parts[4]}"
    WF_INPUT="${parts[5]}"

    if ! grep -qE "^  ${PARAM}:$" "$CFN_TEMPLATE"; then
        echo "❌ CFN parameter ${PARAM} not declared"
        FAILED=1
    fi

    if ! grep -qE "^  ${COND}: !Not \[!Equals \[!Ref ${PARAM}, ''\]\]$" "$CFN_TEMPLATE"; then
        echo "❌ Condition ${COND} not declared"
        FAILED=1
    fi

    if ! grep -B1 -A3 -E "^[[:space:]]+- ${COND}$" "$CFN_TEMPLATE" \
            | grep -qE "Name: ${ENV_VAR}$"; then
        echo "❌ Agent container env block does not conditionally inject ${ENV_VAR}"
        FAILED=1
    fi

    if ! grep -qE "${OVERRIDE_VAR}:-\\\$\\(yq eval[[:space:]]+'\.deployment\.${YAML_KEY}[[:space:]]+//[[:space:]]+\"\"'" "$DEPLOY_SCRIPT"; then
        echo "❌ Deploy script does not resolve via \${${OVERRIDE_VAR}:-yq...}"
        FAILED=1
    fi

    if ! grep -qE "\"${PARAM}=\\\$" "$DEPLOY_SCRIPT"; then
        echo "❌ Deploy script does not pass ${PARAM} into PARAMS"
        FAILED=1
    fi

    if ! grep -qE "^      ${WF_INPUT}:$" "$DEPLOY_WORKFLOW"; then
        echo "❌ Workflow does not expose input '${WF_INPUT}'"
        FAILED=1
    fi

    if ! grep -qE "${OVERRIDE_VAR}: \\\$\\{\\{ inputs\.${WF_INPUT} \\}\\}" "$DEPLOY_WORKFLOW"; then
        echo "❌ Workflow does not plumb ${OVERRIDE_VAR}"
        FAILED=1
    fi

    if ! grep -qE "envIntDefault\(\"${ENV_VAR}\"" "$AGENT_RUN"; then
        echo "❌ Agent run.go does not call envIntDefault(\"${ENV_VAR}\", ...)"
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    exit 1
fi

echo "✅ Circuit breaker threshold env vars plumb end-to-end."
