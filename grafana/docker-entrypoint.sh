#!/bin/sh
# AxonFlow Grafana Entrypoint
# Generates datasources.yaml from environment variables at container startup
#
# This pattern is standard for containerized applications that need dynamic configuration.
# Environment variables are passed from CloudFormation via ECS task definition:
#   - STACK_NAME: Used to construct Prometheus URL (prometheus.${STACK_NAME}.local)
#   - GF_DATABASE_HOST: RDS PostgreSQL endpoint
#   - GF_DATABASE_USER: Database user
#   - GF_DATABASE_PASSWORD: Database password (from Secrets Manager)

set -e

# Default to 'axonflow' if STACK_NAME not set (for local testing)
STACK_NAME="${STACK_NAME:-axonflow}"
NAMESPACE="${STACK_NAME}.local"

# Prometheus URL - uses ECS Service Connect / Cloud Map DNS.
# The axonflow-prometheus image is started with --web.external-url=/prometheus
# (see platform/monitoring/Dockerfile), so Prometheus serves its API under the
# /prometheus route-prefix. The datasource URL MUST include that subpath or
# every Grafana query and datasource "Save & test" returns HTTP 404. The host
# alias is reachable as-is; only the path was missing.
PROMETHEUS_URL="${PROMETHEUS_URL:-http://prometheus.${NAMESPACE}:9090/prometheus}"

# Database settings from environment (set by CloudFormation)
# Note: GF_DATABASE_HOST from CloudFormation includes port (host:5432)
# For local testing, we default to just "postgres" and add port below
DB_HOST_RAW="${GF_DATABASE_HOST:-postgres:5432}"
DB_USER="${GF_DATABASE_USER:-grafana}"
DB_PASSWORD="${GF_DATABASE_PASSWORD:-localdev123}"
DB_NAME="${GF_DATABASE_NAME:-axonflow}"
DB_SSL_MODE="${GF_DATABASE_SSL_MODE:-require}"

# PostgreSQL DATASOURCE settings (what SQL dashboard panels query — the
# platform database with usage_events / organizations, NOT Grafana's own
# metadata DB). On deployments where GF_DATABASE_* points at a dedicated
# `grafana` metadata database (e.g. the marketplace CFN stacks), set the
# USAGE_DB_* variables to a read-scoped platform-DB credential or the SQL
# panels will query a database that has no usage tables. They default to
# the GF_DATABASE_* values so local/single-DB setups keep working. NB: the
# platform's usage tables are row-level-secured — the datasource role must
# be the table owner or BYPASSRLS, otherwise every query silently returns
# zero rows.
USAGE_DB_HOST_RAW="${USAGE_DB_HOST:-${DB_HOST_RAW}}"
USAGE_DB_USER="${USAGE_DB_USER:-${DB_USER}}"
USAGE_DB_PASSWORD="${USAGE_DB_PASSWORD:-${DB_PASSWORD}}"
USAGE_DB_NAME="${USAGE_DB_NAME:-${DB_NAME}}"
USAGE_DB_SSL_MODE="${USAGE_DB_SSL_MODE:-${DB_SSL_MODE}}"

echo "AxonFlow Grafana Configuration"
echo "=============================="
echo "Stack Name: ${STACK_NAME}"
echo "DNS Namespace: ${NAMESPACE}"
echo "Prometheus URL: ${PROMETHEUS_URL}"
echo "Database Host: ${DB_HOST_RAW}"
echo "Database User: ${DB_USER}"
echo "Database Name: ${DB_NAME}"
echo "SSL Mode: ${DB_SSL_MODE}"
echo ""

# Generate datasources.yaml with dynamic values
cat > /etc/grafana/provisioning/datasources/datasources.yaml << EOF
# AxonFlow Grafana Datasources
# Auto-generated for stack: ${STACK_NAME}

apiVersion: 1

datasources:
  # Prometheus - primary metrics source
  # Stable uid: the baked dashboards reference datasources by uid
  # ({"uid": "prometheus"}); without it Grafana assigns a random uid and
  # every uid-referencing panel shows "datasource not found".
  - name: Prometheus
    type: prometheus
    uid: prometheus
    access: proxy
    url: ${PROMETHEUS_URL}
    isDefault: true
    editable: true
    jsonData:
      timeInterval: "15s"
      httpMethod: "POST"

  # PostgreSQL - for node usage and business metrics
  # Stable uid: referenced by the Claude Code Usage dashboard
  # ({"uid": "axonflow-postgres"}). Older dashboards that reference the
  # datasource by name ("PostgreSQL") keep resolving by name.
  - name: PostgreSQL
    type: postgres
    uid: axonflow-postgres
    url: ${USAGE_DB_HOST_RAW}
    database: ${USAGE_DB_NAME}
    user: ${USAGE_DB_USER}
    secureJsonData:
      password: "${USAGE_DB_PASSWORD}"
    jsonData:
      sslmode: ${USAGE_DB_SSL_MODE}
      maxOpenConns: 5
      maxIdleConns: 2
      connMaxLifetime: 14400
    editable: true
EOF

echo "Datasources configuration generated successfully."
echo ""
echo "Configured datasources:"
echo "  - Prometheus: ${PROMETHEUS_URL}"
echo "  - PostgreSQL: ${USAGE_DB_HOST_RAW}/${USAGE_DB_NAME}"
echo ""
echo "Starting Grafana..."

# Execute Grafana with all passed arguments
exec /run.sh "$@"
