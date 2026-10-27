#!/usr/bin/env bash
# Regression test for the bundled axonflow-grafana datasource generator (#2848).
#
# Two behaviors locked here:
#
# 1. Stable datasource uids. The baked dashboards reference datasources by uid
#    ({"uid": "prometheus"} / {"uid": "axonflow-postgres"}). Pre-#2848 the
#    entrypoint emitted no uids, so a fresh deployed Grafana assigned random
#    ones and every uid-referencing panel showed "datasource not found".
#
# 2. USAGE_DB_* override. The PostgreSQL DATASOURCE must be steerable to the
#    platform database (usage_events) independently of GF_DATABASE_* — on the
#    marketplace CFN stacks GF_DATABASE_* points at Grafana's own metadata DB,
#    which has no usage tables (#2849). With no USAGE_DB_* set, the datasource
#    must fall back to the exact pre-#2848 values so local/single-DB setups
#    are untouched.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENTRYPOINT="${SCRIPT_DIR}/../docker-entrypoint.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Same harness as prometheus_datasource_url_test.sh: run the real entrypoint
# with the output redirected and the Grafana exec neutralised.
sed \
  -e "s#/etc/grafana/provisioning/datasources/datasources.yaml#${TMP}/datasources.yaml#g" \
  -e "s#^exec /run.sh.*#exit 0#" \
  "$ENTRYPOINT" > "$TMP/entrypoint.sh"

fail() { echo "FAIL: $1"; exit 1; }

# Extract the value of a key within one datasource block (from its `- name:`
# line to the next `- name:` or EOF).
ds_field() { # $1=file $2=datasource name $3=key
  awk -v ds="$2" -v key="$3" '
    $0 ~ "- name: " ds {p=1; next}
    p && /- name: /{p=0}
    p && $1 == key":" {print $2; exit}
  ' "$1"
}

# --- Case 1: no env — defaults must match pre-#2848 behavior, plus uids ----
STACK_NAME=axonflow sh "$TMP/entrypoint.sh" >/dev/null 2>&1
G="$TMP/datasources.yaml"
[ -f "$G" ] || fail "entrypoint did not generate datasources.yaml"

[ "$(ds_field "$G" Prometheus uid)" = "prometheus" ] \
  || fail "Prometheus datasource missing stable uid 'prometheus' (baked dashboards reference it)"
[ "$(ds_field "$G" PostgreSQL uid)" = "axonflow-postgres" ] \
  || fail "PostgreSQL datasource missing stable uid 'axonflow-postgres' (Claude Code Usage dashboard references it)"

[ "$(ds_field "$G" PostgreSQL url)" = "postgres:5432" ]  || fail "default PostgreSQL url changed"
[ "$(ds_field "$G" PostgreSQL database)" = "axonflow" ]  || fail "default PostgreSQL database changed"
[ "$(ds_field "$G" PostgreSQL user)" = "grafana" ]       || fail "default PostgreSQL user changed"
[ "$(ds_field "$G" PostgreSQL sslmode)" = "require" ]    || fail "default PostgreSQL sslmode changed"
echo "PASS: defaults — stable uids present, PostgreSQL datasource falls back to GF_DATABASE_* values"

# --- Case 2: USAGE_DB_* set — only the datasource retargets ----------------
rm -f "$G"
STACK_NAME=axonflow \
  GF_DATABASE_HOST=grafana-meta:5432 GF_DATABASE_NAME=grafana GF_DATABASE_USER=grafana \
  USAGE_DB_HOST=platform-db:5432 USAGE_DB_NAME=axonflow USAGE_DB_USER=axonflow_readonly \
  USAGE_DB_PASSWORD=sekrit USAGE_DB_SSL_MODE=verify-full \
  sh "$TMP/entrypoint.sh" >/dev/null 2>&1
[ -f "$G" ] || fail "entrypoint did not generate datasources.yaml (override case)"

[ "$(ds_field "$G" PostgreSQL url)" = "platform-db:5432" ]      || fail "USAGE_DB_HOST not applied to the datasource"
[ "$(ds_field "$G" PostgreSQL database)" = "axonflow" ]         || fail "USAGE_DB_NAME not applied to the datasource"
[ "$(ds_field "$G" PostgreSQL user)" = "axonflow_readonly" ]    || fail "USAGE_DB_USER not applied to the datasource"
[ "$(ds_field "$G" PostgreSQL sslmode)" = "verify-full" ]       || fail "USAGE_DB_SSL_MODE not applied to the datasource"
grep -q 'password: "sekrit"' "$G"                               || fail "USAGE_DB_PASSWORD not applied to the datasource"
[ "$(ds_field "$G" PostgreSQL uid)" = "axonflow-postgres" ]     || fail "uid must stay stable under USAGE_DB_* override"
echo "PASS: USAGE_DB_* retargets the PostgreSQL datasource without touching its uid"
