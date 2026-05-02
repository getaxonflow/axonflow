#!/usr/bin/env bash
# Regression guard: the saas-perf-testing env config must keep parity with
# in-vpc-enterprise on every dimension EXCEPT the load balancer scheme.
# Both stacks exist for a single purpose — comparable monthly perf data
# across the in-VPC and SaaS topologies — and the only varied dimension
# should be the ALB scheme (internal vs internet-facing). If a future
# refactor accidentally changes the replica count, DB instance class, or
# Ollama endpoint on one but not the other, the headline numbers stop
# being comparable and the perf-tracking story breaks.

set -euo pipefail

INVPC=config/environments/in-vpc-enterprise.yaml
SAAS=config/environments/saas-perf-testing.yaml

if [ ! -f "$INVPC" ] || [ ! -f "$SAAS" ]; then
    echo "❌ env config files missing"
    exit 1
fi

FAILED=0

# 1. saas-perf-testing must be internet-facing.
SCHEME=$(yq eval '.deployment.load_balancer.scheme' "$SAAS")
if [ "$SCHEME" != "internet-facing" ]; then
    echo "❌ $SAAS load_balancer.scheme = '$SCHEME', must be 'internet-facing'"
    FAILED=1
fi

# 2. in-vpc-enterprise must stay internal (don't accidentally flip).
INVPC_SCHEME=$(yq eval '.deployment.load_balancer.scheme' "$INVPC")
if [ "$INVPC_SCHEME" != "internal" ]; then
    echo "❌ $INVPC load_balancer.scheme = '$INVPC_SCHEME', must be 'internal'"
    FAILED=1
fi

# 3. Identical comparison axes — the things that MUST match for the two
# stacks to produce comparable numbers. Each row: yq path | label.
PARITY_AXES=(
    ".containers.agent.replicas|agent replica count"
    ".containers.agent.cpu|agent CPU"
    ".containers.agent.memory|agent memory"
    ".containers.orchestrator.replicas|orchestrator replica count"
    ".containers.orchestrator.cpu|orchestrator CPU"
    ".containers.orchestrator.memory|orchestrator memory"
    ".deployment.database.instance_class|DB instance class"
    ".deployment.database.multi_az|DB multi-AZ"
    ".deployment.OllamaEndpoint|Ollama endpoint"
    ".deployment.OllamaModel|Ollama model"
    ".deployment.deploy_performance_testing|perf-testing infra deployment"
)

for axis in "${PARITY_AXES[@]}"; do
    path="${axis%%|*}"
    label="${axis##*|}"
    invpc_val=$(yq eval "$path" "$INVPC")
    saas_val=$(yq eval "$path" "$SAAS")
    if [ "$invpc_val" != "$saas_val" ]; then
        echo "❌ $label diverged: in-vpc='$invpc_val' vs saas='$saas_val' — must match for comparable perf data"
        FAILED=1
    fi
done

# 4. saas-perf-testing must use saas DeploymentMode (not in-vpc-* — those
# trigger different orchestrator route registration and would not measure
# a SaaS-shaped path).
SAAS_DM=$(yq eval '.deployment.DeploymentMode' "$SAAS")
if [ "$SAAS_DM" != "saas" ]; then
    echo "❌ $SAAS DeploymentMode = '$SAAS_DM', must be 'saas' for the SaaS-shaped benchmark"
    FAILED=1
fi

# 5. deploy-platform.yml + seed-test-data.yml must accept saas-perf-testing
# as a workflow_dispatch environment input, and the seed gate condition
# in deploy-platform.yml must include it.
if ! grep -qE "^          - saas-perf-testing$" .github/workflows/deploy-platform.yml; then
    echo "❌ deploy-platform.yml does not list 'saas-perf-testing' as an environment option"
    FAILED=1
fi
if ! grep -qE "inputs\.environment == 'saas-perf-testing'" .github/workflows/deploy-platform.yml; then
    echo "❌ deploy-platform.yml seed-test-data gate does not include 'saas-perf-testing'"
    FAILED=1
fi
if ! grep -qE "^          - saas-perf-testing$" .github/workflows/seed-test-data.yml; then
    echo "❌ seed-test-data.yml does not list 'saas-perf-testing' as an environment option"
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Effect: the SaaS-vs-in-VPC perf comparison either stops being"
    echo "comparable (replicas/DB/Ollama divergence) or stops being deployable"
    echo "(workflow gates miss the env)."
    exit 1
fi

echo "✅ saas-perf-testing config keeps parity with in-vpc-enterprise on every axis except load_balancer.scheme."
