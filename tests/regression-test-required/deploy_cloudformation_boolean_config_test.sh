#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEPLOY_SCRIPT="$ROOT_DIR/scripts/deployment/deploy-cloudformation.sh"
STAGING_CONFIG="$ROOT_DIR/config/environments/community-saas-staging.yaml"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

for tool in yq rg; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done

for key in deploy_prometheus deploy_grafana; do
  value=$(yq eval ".deployment.${key}" "$STAGING_CONFIG")
  [ "$value" = "false" ] || fail "$key must remain explicitly false in staging"
done

for key in deploy_customer_portal deploy_customer_portal_ui; do
  value=$(yq eval ".deployment.${key}" "$STAGING_CONFIG")
  [ "$value" = "true" ] || fail "$key must be explicitly enabled for Hosted staging certification"
done

[ -n "$(yq eval '.hosted_starter.portal_certificate_arn // ""' "$STAGING_CONFIG")" ] || \
  fail "Hosted staging must declare the dedicated Portal ACM certificate"

[ -z "$(yq eval '.hosted_starter.module_capabilities // ""' "$STAGING_CONFIG")" ] || \
  fail "Hosted staging must not advertise workflow modules before acceptance"

[ "$(yq eval '.deployment.EnabledLLMProviders // ""' "$STAGING_CONFIG")" = "openai" ] || \
  fail "Hosted staging must use its reachable OpenAI provider"
[ "$(yq eval '.deployment.OpenAIModel // ""' "$STAGING_CONFIG")" = "gpt-4.1" ] || \
  fail "Hosted staging must pin the certified OpenAI model"
[ "$(yq eval '.secrets.openai_credentials // ""' "$STAGING_CONFIG")" = "axonflow/staging/openai-credentials" ] || \
  fail "Hosted staging must select the existing staging OpenAI credential"
[ "$(yq eval '.hosted_starter.monthly_price_id // ""' "$STAGING_CONFIG")" = "price_1UU2LzCokRiQkpTD0SJbtJNS" ] || \
  fail "Hosted staging must select the verified recurring Stripe test price"

if rg -n '\.deployment\.deploy_[a-z_]+ // ("?true"?|"?false"?)' "$DEPLOY_SCRIPT"; then
  fail "deployment booleans must not use yq // because it replaces explicit false"
fi

for assignment in \
  "DEPLOY_CUSTOMER_PORTAL=\$(yaml_bool '.deployment.deploy_customer_portal' true)" \
  "DEPLOY_CUSTOMER_PORTAL_UI=\$(yaml_bool '.deployment.deploy_customer_portal_ui' true)" \
  "DEPLOY_PROMETHEUS=\$(yaml_bool '.deployment.deploy_prometheus' true)" \
  "DEPLOY_GRAFANA=\$(yaml_bool '.deployment.deploy_grafana' true)" \
  "DEPLOY_PERFORMANCE_TESTING=\$(yaml_bool '.deployment.deploy_performance_testing' false)"
do
  rg -F --quiet "$assignment" "$DEPLOY_SCRIPT" || \
    fail "missing safe boolean read: $assignment"
done

for parameter in \
  'CustomerPortalDesiredCount=$PORTAL_REPLICAS' \
  'HostedPortalDomainName=$HOSTED_PORTAL_DOMAIN' \
  'HostedPortalCertificateArn=$HOSTED_PORTAL_CERTIFICATE_ARN' \
  'HostedPortalFromEmail=$HOSTED_PORTAL_FROM_EMAIL' \
  'HostedModuleCapabilities=$HOSTED_MODULE_CAPABILITIES' \
  'AdminAPIKeySecretArn=${ADMIN_API_KEY_ARN:-}' \
  'AppRoleProvisioned=$APP_ROLE_PROVISIONED' \
  'DBAppRoleURLSecretArn=${DB_APP_ROLE_URL_SECRET_ARN:-}' \
  'DBPlatformAdminURLSecretArn=${DB_PLATFORM_ADMIN_URL_SECRET_ARN:-}'
do
  rg -F --quiet "$parameter" "$DEPLOY_SCRIPT" || fail "missing Hosted Portal parameter: $parameter"
done

rg -F --quiet 'STACK_NAME="${STACK_NAME_OVERRIDE:-${STACK_PREFIX}-${TIMESTAMP}}"' "$DEPLOY_SCRIPT" || \
  fail "same-stack update override is missing"
rg -F --quiet '[[ "$STACK_NAME" != "${STACK_PREFIX}-"* ]]' "$DEPLOY_SCRIPT" || \
  fail "stack-name override prefix validation is missing"
rg -F --quiet "OPENAI_SECRET=\$(yq eval '.secrets.openai_credentials // \"\"' \"\$CONFIG_FILE\")" "$DEPLOY_SCRIPT" || \
  fail "OpenAI credential selection must support an environment config override"
rg -F --quiet "ANTHROPIC_SECRET=\$(yq eval '.secrets.anthropic_credentials // \"\"' \"\$CONFIG_FILE\")" "$DEPLOY_SCRIPT" || \
  fail "Anthropic credential selection must support an environment config override"

rg -F --quiet 'PARAMS_FILE=$(mktemp "${TMPDIR:-/tmp}/axonflow-cfn-params.XXXXXX")' "$DEPLOY_SCRIPT" || \
  fail "CloudFormation parameters must be written to a restrictive temporary file"
rg -F --quiet 'umask 077' "$DEPLOY_SCRIPT" || \
  fail "CloudFormation parameter files must be private from their first filesystem write"
rg -F --quiet 'trap cleanup_params_file EXIT' "$DEPLOY_SCRIPT" || \
  fail "temporary CloudFormation parameters must be removed on every exit path"
rg -F --quiet -- '--parameter-overrides "file://$PARAMS_FILE"' "$DEPLOY_SCRIPT" || \
  fail "CloudFormation deploy must receive only the temporary parameter file path"
if rg -F --quiet -- '--parameter-overrides "${PARAMS[@]}"' "$DEPLOY_SCRIPT"; then
  fail "CloudFormation deploy must not expose expanded parameter values in argv"
fi

echo "PASS: deploy-cloudformation preserves explicit false values and supports guarded same-stack updates"
