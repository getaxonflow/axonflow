#!/usr/bin/env bash
# Regression test for the bundled axonflow-grafana datasource generator.
#
# Bug (QF / regression-test-per-bug): docker-entrypoint.sh generated the
# Prometheus datasource URL without the `/prometheus` route-prefix that the
# bundled axonflow-prometheus image serves under (`--web.external-url=/prometheus`,
# platform/monitoring/Dockerfile). Result: every Grafana query / datasource
# "Save & test" returned HTTP 404 and all metrics dashboards rendered empty.
#
# This test exercises the entrypoint's datasource-generation layer directly:
# it runs the real entrypoint (with the Grafana exec neutralised and the output
# redirected to a temp file) and asserts the generated Prometheus datasource URL
# carries the /prometheus subpath. It fails against the pre-fix entrypoint.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRYPOINT="${SCRIPT_DIR}/../docker-entrypoint.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Run a copy of the entrypoint with: (1) the datasources output redirected to a
# temp file, and (2) the final `exec /run.sh` replaced with a clean exit so we
# never try to launch Grafana.
sed \
  -e "s#/etc/grafana/provisioning/datasources/datasources.yaml#${TMP}/datasources.yaml#g" \
  -e "s#^exec /run.sh.*#exit 0#" \
  "$ENTRYPOINT" > "$TMP/entrypoint.sh"

STACK_NAME=axonflow sh "$TMP/entrypoint.sh" >/dev/null 2>&1

GENERATED="$TMP/datasources.yaml"
[ -f "$GENERATED" ] || { echo "FAIL: entrypoint did not generate datasources.yaml"; exit 1; }

# The Prometheus datasource URL must include the /prometheus subpath.
PROM_URL="$(awk '/name: Prometheus/{p=1} p && /url:/{print $2; exit}' "$GENERATED")"
echo "Generated Prometheus datasource URL: ${PROM_URL}"

EXPECTED="http://prometheus.axonflow.local:9090/prometheus"
if [ "$PROM_URL" != "$EXPECTED" ]; then
  echo "FAIL: expected Prometheus datasource URL '${EXPECTED}', got '${PROM_URL}'"
  echo "      (bundled axonflow-prometheus serves under --web.external-url=/prometheus;"
  echo "       a path-less URL returns HTTP 404 on every Grafana query)"
  exit 1
fi

# Belt-and-suspenders: reject any path-less :9090 Prometheus URL.
case "$PROM_URL" in
  *":9090/prometheus") : ;;
  *":9090"|*":9090/") echo "FAIL: Prometheus URL is missing the /prometheus route-prefix"; exit 1 ;;
esac

echo "PASS: Prometheus datasource URL carries the /prometheus subpath"

# Local Compose uses the same image but a non-Cloud-Map service name. Its
# explicit URL must win without weakening the production default above.
rm -f "$GENERATED"
PROMETHEUS_URL=http://prometheus:9090/prometheus \
  STACK_NAME=ignored-by-override \
  sh "$TMP/entrypoint.sh" >/dev/null 2>&1
OVERRIDE_URL="$(awk '/name: Prometheus/{p=1} p && /url:/{print $2; exit}' "$GENERATED")"
[ "$OVERRIDE_URL" = "http://prometheus:9090/prometheus" ] || {
  echo "FAIL: PROMETHEUS_URL override was not preserved (got '${OVERRIDE_URL}')"
  exit 1
}

echo "PASS: explicit Prometheus datasource URL overrides the Cloud Map default"
