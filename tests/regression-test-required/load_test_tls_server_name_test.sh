#!/usr/bin/env bash
# Regression guard: the load-test harness must honor LOAD_TEST_TLS_SERVER_NAME
# env var and pass it to tls.Config.ServerName, so cert validation works when
# the URL host (e.g. internal-axonfl-...elb.amazonaws.com) doesn't match the
# ACM cert hostname (e.g. try.getaxonflow.com) but the cert is legitimately
# attached to that listener.
#
# The risk this guards against: a future refactor of the transport setup
# silently drops the ServerName line. The next perf run against the in-VPC
# stack with HTTPS+H2 then fails every request with "x509: certificate is
# valid for try.getaxonflow.com, not internal-axonfl-...". Caught at PR
# review time, not at perf-run time.

set -euo pipefail

HARNESS="ee/platform/load-testing/sustained_load.go"

if [ ! -f "$HARNESS" ]; then
    echo "❌ $HARNESS not found"
    exit 1
fi

FAILED=0

# 1. Env var must be read.
if ! grep -qE 'os\.Getenv\("LOAD_TEST_TLS_SERVER_NAME"\)' "$HARNESS"; then
    echo "❌ $HARNESS does not read os.Getenv(\"LOAD_TEST_TLS_SERVER_NAME\")"
    FAILED=1
fi

# 2. The value must be assigned to a local variable that gets used in tls.Config.
#    Match: tlsServerName := os.Getenv("LOAD_TEST_TLS_SERVER_NAME")
if ! grep -qE 'tlsServerName[[:space:]]*:?=[[:space:]]*os\.Getenv\("LOAD_TEST_TLS_SERVER_NAME"\)' "$HARNESS"; then
    echo "❌ $HARNESS does not assign LOAD_TEST_TLS_SERVER_NAME to tlsServerName"
    FAILED=1
fi

# 3. tls.Config struct literal must include ServerName: tlsServerName.
#    Match across lines via awk: in the &tls.Config{...} block, find ServerName: tlsServerName.
if ! awk '
    /&tls\.Config\{/ { in_block = 1 }
    in_block && /ServerName:[[:space:]]+tlsServerName/ { found = 1; exit }
    in_block && /^\s*\},/ { in_block = 0 }
    END { exit (found ? 0 : 1) }
' "$HARNESS"; then
    echo "❌ $HARNESS tls.Config does not set ServerName: tlsServerName"
    FAILED=1
fi

# 4. Documentation comment must explain that ServerName is NOT a SKIP_TLS_VERIFY
#    substitute — cert chain still validates against the override SNI. Without
#    this, future readers may think the field disables verification.
if ! grep -qiE "(NOT a SKIP_TLS_VERIFY|cert chain MUST match|cert validation stays on)" "$HARNESS"; then
    echo "❌ $HARNESS lacks comment clarifying ServerName ≠ skip-verify"
    FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Effect: load-test runs against an internal ALB with a shared public"
    echo "cert fail every TLS handshake. Numbers are unmeasurable."
    exit 1
fi

echo "✅ Load-test harness honors LOAD_TEST_TLS_SERVER_NAME for SNI override."
