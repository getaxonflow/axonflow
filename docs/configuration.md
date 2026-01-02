# Configuration Reference

AxonFlow is designed with secure-by-default settings that are fully configurable. This document covers all environment variables for controlling security detection and policy enforcement.

## Security Configuration

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `PII_BLOCK_CRITICAL` | `true`, `false` | `true` | Block requests containing critical PII (SSN, Aadhaar, credit cards, etc.) |
| `SQLI_SCANNER_MODE` | `off`, `basic`, `advanced` | `basic` | SQL injection scanning mode |
| `SQLI_BLOCK_MODE` | `block`, `warn` | `block` | Action on SQLi detection |

### Starting in Observe-Only Mode

For evaluation or development, you can run AxonFlow in observe-only mode where all detections are logged but not blocked:

```yaml
environment:
  PII_BLOCK_CRITICAL: "false"  # Log only, don't block
  SQLI_BLOCK_MODE: "warn"      # Warn only, don't block
```

This allows you to see what AxonFlow would detect without impacting your application. Once you've validated detection accuracy in your environment, you can enable blocking.

### Progressive Enforcement

A common adoption pattern:

1. **Week 1-2: Observe** - Run with `PII_BLOCK_CRITICAL=false` and `SQLI_BLOCK_MODE=warn`
2. **Week 3-4: Validate** - Review audit logs, tune any false positives
3. **Week 5+: Enforce** - Enable blocking with confidence

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

## Environment Variable Precedence

1. **Per-connector config** (highest priority)
2. **Environment variables**
3. **Default values** (lowest priority)

## Docker Compose Example

```yaml
services:
  axonflow-agent:
    environment:
      # === Security Detection Configuration ===
      # All enforcement is configurable. Start in observe-only mode for evaluation,
      # then progressively enable blocking as confidence grows.
      #
      # PII Detection: Set to "false" to log-only (no blocking)
      PII_BLOCK_CRITICAL: "true"
      #
      # SQLi Scanner: "off", "basic" (default), "advanced" (enterprise)
      SQLI_SCANNER_MODE: "basic"
      #
      # SQLi Action: "block" (default) or "warn" (log + allow)
      SQLI_BLOCK_MODE: "block"

      # === Deployment Mode ===
      # "community" = no auth required, "enterprise" = license required
      DEPLOYMENT_MODE: "community"
```

## Related Documentation

- [PII Detection](/docs/security/pii-detection.md) - Supported PII types and configuration
- [SQL Injection Scanning](/docs/security/sql-injection-scanning.md) - SQLi detection modes
- [Policy Enforcement](/docs/policies/) - Custom policy rules
