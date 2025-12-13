# AxonFlow Community Configuration Guide

This guide explains how to configure AxonFlow for self-hosted and Community deployments using configuration files instead of the Customer Portal.

## Overview

AxonFlow supports a three-tier configuration system:

| Priority | Source | Use Case |
|----------|--------|----------|
| 1 (Highest) | Database | Enterprise deployments via Customer Portal |
| 2 | Config File | Community/self-hosted deployments |
| 3 (Lowest) | Environment Variables | Legacy compatibility, CI/CD |

For Community deployments, the **config file** is the recommended approach.

## Quick Start

### 1. Create Configuration File

Copy the example configuration:

```bash
mkdir -p config
cp examples/config/axonflow.yaml.example config/axonflow.yaml
```

### 2. Edit Configuration

```yaml
version: "1.0"

connectors:
  my_postgres:
    type: postgres
    enabled: true
    connection_url: ${DATABASE_URL}
    credentials:
      username: ${POSTGRES_USER:-postgres}
      password: ${POSTGRES_PASSWORD}

llm_providers:
  bedrock:
    enabled: true
    config:
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
    priority: 10
```

### 3. Set Environment Variables

```bash
export DATABASE_URL="postgres://localhost:5432/myapp"
export POSTGRES_USER="myuser"
export POSTGRES_PASSWORD="mypassword"
```

### 4. Start AxonFlow

```bash
# Option 1: Auto-detect config file (./axonflow.yaml or ./config/axonflow.yaml)
./axonflow-agent

# Option 2: Explicit config file path
AXONFLOW_CONFIG_FILE=/path/to/config.yaml ./axonflow-agent
```

## Configuration File Locations

AxonFlow searches for configuration files in this order:

1. `$AXONFLOW_CONFIG_FILE` (environment variable)
2. `./axonflow.yaml` (current directory)
3. `./config/axonflow.yaml`
4. `/etc/axonflow/axonflow.yaml`

## Environment Variable Expansion

Configuration files support environment variable expansion:

```yaml
# Direct reference
connection_url: ${DATABASE_URL}

# With default value
connection_url: ${DATABASE_URL:-postgres://localhost:5432/default}

# Both syntaxes work
username: $POSTGRES_USER
password: ${POSTGRES_PASSWORD}
```

## Connector Configuration

### Supported Connector Types

| Type | Description | Example Use Cases |
|------|-------------|-------------------|
| `postgres` | PostgreSQL databases | Application data, analytics |
| `cassandra` | Cassandra/ScyllaDB | Time-series, high-throughput |
| `snowflake` | Snowflake data warehouse | Business intelligence |
| `salesforce` | Salesforce CRM | Customer data |
| `slack` | Slack workspace | Team communication |
| `amadeus` | Travel APIs | Flight/hotel search |

### Common Connector Options

```yaml
connectors:
  my_connector:
    type: postgres              # Required: connector type
    enabled: true               # Required: enable/disable
    display_name: "My DB"       # Optional: human-readable name
    description: "Description"  # Optional: description

    connection_url: "..."       # Connection string

    credentials:                # Authentication
      username: "..."
      password: "..."

    options:                    # Type-specific options
      schema: "public"
      ssl_mode: "require"

    timeout_ms: 30000          # Query timeout (default: 30000)
    max_retries: 3             # Retry attempts (default: 3)
    tenant_id: "*"             # Tenant filter (default: "*" = all)
```

### PostgreSQL Connector

```yaml
connectors:
  postgres_main:
    type: postgres
    enabled: true
    connection_url: postgres://host:5432/database
    credentials:
      username: ${POSTGRES_USER}
      password: ${POSTGRES_PASSWORD}
    options:
      max_open_conns: 25
      max_idle_conns: 5
      conn_max_lifetime: "5m"
      schema: "public"
      ssl_mode: "require"      # disable, require, verify-full
```

### Cassandra Connector

```yaml
connectors:
  cassandra_cluster:
    type: cassandra
    enabled: true
    credentials:
      hosts: "host1,host2,host3"
      port: 9042
      username: ${CASSANDRA_USER}
      password: ${CASSANDRA_PASSWORD}
      keyspace: "my_keyspace"
    options:
      consistency: "QUORUM"
      dc: "datacenter1"
```

### Snowflake Connector

```yaml
connectors:
  snowflake_warehouse:
    type: snowflake
    enabled: true
    credentials:
      account: ${SNOWFLAKE_ACCOUNT}
      username: ${SNOWFLAKE_USER}
      password: ${SNOWFLAKE_PASSWORD}
      # Or key-pair auth:
      # private_key_path: /path/to/key.p8
    options:
      warehouse: "COMPUTE_WH"
      database: "MY_DB"
      schema: "PUBLIC"
      role: "MY_ROLE"
```

## LLM Provider Configuration

### Supported Providers

| Provider | Authentication | Best For |
|----------|---------------|----------|
| `bedrock` | AWS IAM | AWS deployments |
| `ollama` | None | Self-hosted, private |
| `openai` | API Key | OpenAI models |
| `anthropic` | API Key | Direct Claude access |

### Load Balancing and Failover

Configure multiple providers with priority and weight:

```yaml
llm_providers:
  bedrock:
    enabled: true
    priority: 10    # Highest priority = primary
    weight: 0.8     # 80% of traffic

  ollama:
    enabled: true
    priority: 5     # Failover
    weight: 0.2     # 20% of traffic
```

**Routing Logic:**
1. Requests go to highest-priority healthy providers
2. Within same priority, traffic distributed by weight
3. Unhealthy providers are skipped automatically

### Amazon Bedrock

```yaml
llm_providers:
  bedrock:
    enabled: true
    config:
      region: us-east-1
      model: anthropic.claude-3-5-sonnet-20240620-v1:0
    priority: 10
    weight: 1.0
```

### Ollama (Self-hosted)

```yaml
llm_providers:
  ollama:
    enabled: true
    config:
      endpoint: http://localhost:11434
      model: llama3.1:70b
    priority: 5
    weight: 0.5
```

### OpenAI

```yaml
llm_providers:
  openai:
    enabled: true
    config:
      model: gpt-4-turbo
      max_tokens: 4096
    credentials:
      api_key: ${OPENAI_API_KEY}
    priority: 5
    weight: 0.5
```

## Self-Hosted Mode

For fully self-hosted deployments where you want to skip database lookups:

```bash
export AXONFLOW_SELF_HOSTED=true
export AXONFLOW_CONFIG_FILE=/etc/axonflow/config.yaml
```

In self-hosted mode, the config file takes precedence over database configuration.

## Validation

The configuration file is validated on load. Validation checks:

- Version field is present
- Connector types are valid
- LLM provider names are valid
- Weight values are between 0 and 1

### Example Validation Errors

```
Error: config file must specify a version
Error: connector 'my_db' has invalid type 'mysql'
Error: invalid LLM provider 'gpt'
Error: LLM provider 'bedrock' weight must be between 0 and 1
```

## Security Best Practices

1. **Never commit credentials** - Use environment variables
2. **Use default values carefully** - Don't expose sensitive defaults
3. **Restrict file permissions** - `chmod 600 config/axonflow.yaml`
4. **Rotate credentials regularly** - Especially API keys

## Troubleshooting

### Config File Not Found

```
[MCP] Config file loading failed, falling back to env vars
```

Check:
- File exists at expected location
- `AXONFLOW_CONFIG_FILE` is set correctly
- File has read permissions

### Environment Variable Not Expanded

```
connection_url: ${DATABASE_URL}  # Shows literally
```

Ensure:
- Variable is exported: `export DATABASE_URL=...`
- No typos in variable name
- Default value syntax is correct: `${VAR:-default}`

### Connector Registration Failed

```
[MCP] Warning: Failed to register connector 'my_db': ...
```

Check:
- Connector type is supported
- Required credentials are provided
- Connection URL is valid

## Next Steps

- [Contributing a New Connector](./connector-development.md)
- [Policy Configuration](../reference/policy-templates.md)
- [API Reference](../api/)
