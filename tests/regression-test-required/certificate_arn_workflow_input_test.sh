#!/usr/bin/env bash
# Regression guard: deploy-platform.yml's certificate_arn workflow_dispatch
# input must be plumbed through to the ssl_setup step's CERTIFICATE_ARN_OVERRIDE
# env var, and the bash logic in that step must honor the override over the
# yaml read.
#
# Without all three wiring points, an operator passing a certificate ARN
# via -f certificate_arn=<arn> would silently see the workflow ignore it
# and either fall back to the yaml value or run setup-acm-certificate.sh's
# CloudFlare DNS dance — both unintended.

set -euo pipefail

WORKFLOW=".github/workflows/deploy-platform.yml"

if [ ! -f "$WORKFLOW" ]; then
    echo "❌ $WORKFLOW not found"
    exit 1
fi

FAILED=0

# 1. workflow_dispatch input declared.
if ! grep -qE "^      certificate_arn:$" "$WORKFLOW"; then
    echo "❌ $WORKFLOW does not declare workflow_dispatch input 'certificate_arn'"
    FAILED=1
fi

# 2. ssl_setup step env block sets CERTIFICATE_ARN_OVERRIDE: \${{ inputs.certificate_arn }}.
if ! grep -qE 'CERTIFICATE_ARN_OVERRIDE: \$\{\{ inputs\.certificate_arn \}\}' "$WORKFLOW"; then
    echo "❌ $WORKFLOW ssl_setup step does not plumb inputs.certificate_arn → CERTIFICATE_ARN_OVERRIDE env"
    FAILED=1
fi

# 3. ssl_setup step's bash honors the override with proper precedence.
#    Look for: EXISTING_CERT_ARN="${CERTIFICATE_ARN_OVERRIDE:-$(yq eval ...)}"
if ! grep -qE 'EXISTING_CERT_ARN="\$\{CERTIFICATE_ARN_OVERRIDE:-\$\(yq eval' "$WORKFLOW"; then
    echo "❌ $WORKFLOW ssl_setup step bash does not resolve EXISTING_CERT_ARN via \${CERTIFICATE_ARN_OVERRIDE:-yq...}"
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Effect: gh workflow run deploy-platform.yml -f certificate_arn=<arn> is silently"
    echo "ignored; the deploy either falls back to the env yaml's certificate_arn or runs"
    echo "the CloudFlare DNS validation dance."
    exit 1
fi

echo "✅ deploy-platform.yml certificate_arn input plumbs through to ssl_setup correctly."
