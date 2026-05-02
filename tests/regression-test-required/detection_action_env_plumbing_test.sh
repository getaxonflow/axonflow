#!/usr/bin/env bash
# Regression guard: detection action env vars must be plumbed end-to-end
# through CFN parameter → agent container env, and the deploy script must
# pass each one. Without this, the env yaml field looks set but the agent
# never receives the override, and the perf-test stack silently runs at
# default-profile actions even with sqli_action: block in the yaml.
#
# Specifically guards the four operator-facing detection action knobs:
#   SQLI_ACTION, PII_ACTION, SENSITIVE_DATA_ACTION, DANGEROUS_QUERY_ACTION
#
# Each must:
#   1. Have a CFN parameter declaration in cloudformation-ecs-fargate.yaml
#   2. Have a non-empty Conditions: HasXxxAction line
#   3. Be conditionally injected into the agent container Environment block
#      (the `- !If [ HasXxxAction, { Name: XXX_ACTION, Value: ... }, NoValue ]` shape)
#   4. Be read from the env yaml by deploy-cloudformation.sh and passed in
#      the PARAMS array

set -euo pipefail

CFN_TEMPLATE="ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml"
DEPLOY_SCRIPT="scripts/deployment/deploy-cloudformation.sh"
DEPLOY_WORKFLOW=".github/workflows/deploy-platform.yml"

for f in "$CFN_TEMPLATE" "$DEPLOY_SCRIPT" "$DEPLOY_WORKFLOW"; do
    if [ ! -f "$f" ]; then
        echo "❌ $f not found"
        exit 1
    fi
done

# Each row: <CFN-param> <CFN-condition> <env-var> <yaml-field> <override-env> <wf-input>
ACTIONS=(
    "SQLIAction HasSQLIAction SQLI_ACTION sqli_action SQLI_ACTION_OVERRIDE sqli_action"
    "PIIAction HasPIIAction PII_ACTION pii_action PII_ACTION_OVERRIDE pii_action"
    "SensitiveDataAction HasSensitiveDataAction SENSITIVE_DATA_ACTION sensitive_data_action SENSITIVE_DATA_ACTION_OVERRIDE sensitive_data_action"
    "DangerousQueryAction HasDangerousQueryAction DANGEROUS_QUERY_ACTION dangerous_query_action DANGEROUS_QUERY_ACTION_OVERRIDE dangerous_query_action"
)

FAILED=0

for row in "${ACTIONS[@]}"; do
    # shellcheck disable=SC2206
    parts=( $row )
    PARAM="${parts[0]}"
    COND="${parts[1]}"
    ENV_VAR="${parts[2]}"
    YAML_KEY="${parts[3]}"
    OVERRIDE_VAR="${parts[4]}"
    WF_INPUT="${parts[5]}"

    # 1. CFN parameter declaration.
    if ! grep -qE "^  ${PARAM}:$" "$CFN_TEMPLATE"; then
        echo "❌ CFN parameter ${PARAM} is not declared in $CFN_TEMPLATE"
        FAILED=1
    fi

    # 2. Condition declaration in Conditions: block.
    if ! grep -qE "^  ${COND}: !Not \[!Equals \[!Ref ${PARAM}, ''\]\]$" "$CFN_TEMPLATE"; then
        echo "❌ Condition ${COND} is not declared in $CFN_TEMPLATE Conditions: block"
        FAILED=1
    fi

    # 3. Agent + Orchestrator container env injection. Each container that
    #    imports platform/agent/detection_config.go's DetectionConfigFromEnv
    #    needs the override; both agent (run.go) and orchestrator
    #    (run.go + dynamic_policy_engine.go + response_processor.go) do.
    #    Count !If/Name pairs — must be ≥ 2.
    INJECTIONS=$(grep -B1 -A3 -E "^[[:space:]]+- ${COND}$" "$CFN_TEMPLATE" \
            | grep -cE "Name: ${ENV_VAR}$")
    if [ "$INJECTIONS" -lt 2 ]; then
        echo "❌ ${ENV_VAR} is injected via ${COND} only ${INJECTIONS}x in $CFN_TEMPLATE; expected ≥2 (agent + orchestrator containers both consume DetectionConfigFromEnv)"
        FAILED=1
    fi

    # 4. deploy-cloudformation.sh reads the yaml field with the workflow override taking precedence.
    if ! grep -qE "${OVERRIDE_VAR}:-\\\$\\(yq eval[[:space:]]+'\.deployment\.${YAML_KEY}[[:space:]]+//[[:space:]]+\"\"'" "$DEPLOY_SCRIPT"; then
        echo "❌ $DEPLOY_SCRIPT does not resolve ${ENV_VAR} via \${${OVERRIDE_VAR}:-yq .deployment.${YAML_KEY}}"
        FAILED=1
    fi

    # 5. deploy-cloudformation.sh passes the param through PARAMS.
    if ! grep -qE "\"${PARAM}=\\\$" "$DEPLOY_SCRIPT"; then
        echo "❌ $DEPLOY_SCRIPT does not pass ${PARAM} into the CloudFormation PARAMS array"
        FAILED=1
    fi

    # 6. deploy-platform.yml exposes the workflow_dispatch input.
    if ! grep -qE "^      ${WF_INPUT}:$" "$DEPLOY_WORKFLOW"; then
        echo "❌ $DEPLOY_WORKFLOW does not expose workflow_dispatch input '${WF_INPUT}'"
        FAILED=1
    fi

    # 7. deploy-platform.yml plumbs the input into the deploy step's env as <name>_OVERRIDE.
    if ! grep -qE "${OVERRIDE_VAR}: \\\$\\{\\{ inputs\.${WF_INPUT} \\}\\}" "$DEPLOY_WORKFLOW"; then
        echo "❌ $DEPLOY_WORKFLOW does not set env ${OVERRIDE_VAR}: \${{ inputs.${WF_INPUT} }} on the Deploy step"
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Effect of any of the above gaps: the env yaml's <action> field is silently"
    echo "ignored at deploy time. The agent runs at default profile actions even"
    echo "though the operator set the override — and the perf benchmark reports"
    echo "% Success based on HTTP-200 instead of policy-correctness."
    exit 1
fi

echo "✅ All four detection action env vars plumb end-to-end (CFN param → condition → agent env → deploy script)."
