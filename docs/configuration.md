# Configuration Reference

AxonFlow is designed with secure-by-default settings that are fully configurable. This document covers all environment variables for controlling security detection and policy enforcement.

## Security Detection Configuration (Issue #891)

AxonFlow uses a tiered default approach: **block high-confidence threats, warn on heuristics, redact PII**.

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `SQLI_ACTION` | `block`, `warn`, `log` | `block` | SQL injection detection action (high confidence) |
| `PII_ACTION` | `block`, `warn`, `redact`, `log` | `redact` | PII detection action (preserves UX) |
| `SENSITIVE_DATA_ACTION` | `block`, `warn`, `log` | `warn` | Credential/token detection action (may have false positives) |
| `HIGH_RISK_ACTION` | `block`, `warn`, `log` | `warn` | High risk score (>0.8) action (needs tuning) |
| `DANGEROUS_QUERY_ACTION` | `block`, `warn`, `log` | `block` | DROP/TRUNCATE detection action (destructive) |
| `SQLI_SCANNER_MODE` | `off`, `basic`, `advanced` | `basic` | SQL injection scanning mode |

### Action Types

| Action | Behavior |
|--------|----------|
| `block` | Reject request immediately |
| `redact` | Mask/redact detected content, allow request |
| `warn` | Log warning, allow request |
| `log` | Log for audit only, allow request |

### Deprecated Environment Variables

These environment variables are deprecated and will be removed in a future release:

| Deprecated | Replacement | Notes |
|------------|-------------|-------|
| `SQLI_BLOCK_MODE` | `SQLI_ACTION` | `block` → `SQLI_ACTION=block`, `warn` → `SQLI_ACTION=warn` |
| `PII_BLOCK_CRITICAL` | `PII_ACTION` | `true` → `PII_ACTION=block`, `false` → `PII_ACTION=log` |

### Philosophy: Tiered Defaults

The default configuration is designed to minimize friction during evaluation while maintaining security:

| Detection Type | Default | Rationale |
|----------------|---------|-----------|
| SQL Injection | `block` | High confidence, real attacks |
| Dangerous Queries | `block` | Destructive operations |
| PII | `redact` | Non-blocking, preserves user experience |
| Sensitive Data | `warn` | May have false positives (e.g., "PRIMARY KEY") |
| High Risk Score | `warn` | Composite score needs per-environment tuning |

### Progressive Enforcement

A common adoption pattern:

1. **Day 1: Out-of-the-box** - Start with defaults (PII redacted, SQLi blocked)
2. **Week 1: Review** - Check audit logs for detection accuracy
3. **Week 2: Tune** - Adjust actions based on your risk tolerance
4. **Ongoing: Enforce** - Enable stricter blocking as confidence grows

## Environment Variable Precedence

```
┌─────────────────────────────────────────────────────────────────┐
│ Priority 1: Per-tenant policy override (Enterprise API)         │
│   Enterprise users can override any policy via API              │
├─────────────────────────────────────────────────────────────────┤
│ Priority 2: Environment variable (docker-compose)               │
│   SQLI_ACTION=warn overrides all SQLi policies                  │
├─────────────────────────────────────────────────────────────────┤
│ Priority 3: Per-policy DB default (migration seed)              │
│   static_policies.action from seed data                         │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Mode

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `DEPLOYMENT_MODE` | `community`, `enterprise` | `community` | Controls authentication and feature set |

- **community**: No authentication required, all Community features enabled
- **enterprise**: License key required, Enterprise features unlocked

## Per-Connector Overrides

Security settings can be overridden per-connector in your configuration file:

```yaml
# axonflow.yaml
connectors:
  postgresql_main:
    sqli_scanner_mode: advanced  # Use advanced scanning for sensitive DB
  redis_cache:
    sqli_scanner_mode: off       # Disable for trusted internal cache
```

## Docker Compose Example

```yaml
services:
  axonflow-agent:
    environment:
      # === Security Detection Configuration (Issue #891) ===
      # Philosophy: Block high-confidence threats, warn on heuristics, redact PII

      # SQLi Scanner: "off", "basic" (default), "advanced" (enterprise)
      SQLI_SCANNER_MODE: "basic"

      # SQLI_ACTION: block|warn|log (default: block - high confidence attacks)
      SQLI_ACTION: "block"

      # PII_ACTION: block|warn|redact|log (default: redact - preserves UX)
      PII_ACTION: "redact"

      # SENSITIVE_DATA_ACTION: block|warn|log (default: warn - may have false positives)
      SENSITIVE_DATA_ACTION: "warn"

      # HIGH_RISK_ACTION: block|warn|log (default: warn - composite score needs tuning)
      HIGH_RISK_ACTION: "warn"

      # DANGEROUS_QUERY_ACTION: block|warn|log (default: block - DROP/TRUNCATE)
      DANGEROUS_QUERY_ACTION: "block"

      # === Deployment Mode ===
      # "community" = no auth required, "enterprise" = license required
      DEPLOYMENT_MODE: "community"
```

## Legacy Configuration (Deprecated)

For backwards compatibility, the old environment variables still work but will log deprecation warnings:

```yaml
# DEPRECATED - use new *_ACTION variables instead
environment:
  PII_BLOCK_CRITICAL: "true"  # Use PII_ACTION=block instead
  SQLI_BLOCK_MODE: "warn"     # Use SQLI_ACTION=warn instead
```

## Service Ports and Single Entry Point (ADR-024)

AxonFlow implements a **single entry point architecture** where all SDK requests go through the Agent on port 8080. The Agent automatically proxies requests to the appropriate backend service.

| Service | Port | Description |
|---------|------|-------------|
| Agent | 8080 | **Single entry point for all SDK requests** |
| Orchestrator | 8081 | Internal - handles dynamic policies, LLM providers, cost controls |
| Portal | 8082 | Internal - handles auth, code governance (Enterprise) |

### Proxied Routes

The Agent automatically proxies these routes:

| Route Prefix | Proxied To | Purpose |
|--------------|-----------|---------|
| `/api/v1/auth/*` | Portal | Login, logout, session management |
| `/api/v1/code-governance/*` | Portal | Code Governance API |
| `/api/v1/portal/*` | Portal | Portal management |
| `/api/v1/git-providers/*` | Portal | Git provider configuration |
| `/api/v1/dynamic-policies/*` | Orchestrator | Dynamic policy CRUD |
| `/api/v1/connectors/*` | Orchestrator | Connector management |
| `/api/v1/cost/*` | Orchestrator | Cost controls |
| `/api/v1/executions/*` | Orchestrator | Execution replay |
| `/api/v1/llm-providers/*` | Orchestrator | LLM provider configuration |

All other routes (e.g., `/api/v1/policies/*`, `/api/request`, `/health`) are handled directly by the Agent.

### SDK Configuration

Configure your SDK to use only the Agent endpoint:

```go
// Go SDK
client := axonflow.NewClient(axonflow.AxonFlowConfig{
    Endpoint: "http://localhost:8080",  // Single entry point
})
```

```python
# Python SDK
client = AxonFlow(
    endpoint="http://localhost:8080",  # Single entry point
)
```

## Related Documentation

- [PII Detection](/docs/security/pii-detection.md) - Supported PII types and configuration
- [SQL Injection Scanning](/docs/security/sql-injection-scanning.md) - SQLi detection modes
- [Policy Enforcement](/docs/policies/) - Custom policy rules
