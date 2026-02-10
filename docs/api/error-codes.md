# AxonFlow API Error Codes Reference

Complete reference for all error codes returned by AxonFlow APIs.

## Error Response Format

All API errors follow a consistent JSON format:

```json
{
  "success": false,
  "error": "Human-readable error message"
}
```

For validation errors with multiple issues:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "query",
        "message": "Query is required"
      },
      {
        "field": "client_id",
        "message": "Client ID must be alphanumeric"
      }
    ]
  }
}
```

## HTTP Status Codes

| Status | Category | Description |
|--------|----------|-------------|
| 200 | Success | Request processed successfully |
| 201 | Created | Resource created successfully |
| 400 | Client Error | Invalid request (validation failed) |
| 401 | Unauthorized | Authentication required or failed |
| 403 | Forbidden | Access denied (policy, tenant, permissions) |
| 404 | Not Found | Resource does not exist |
| 429 | Rate Limited | Too many requests |
| 500 | Server Error | Internal server error |
| 503 | Unavailable | Service starting or unavailable |

## Authentication Errors (401)

### Missing Credentials

```json
{
  "success": false,
  "error": "Authorization header required"
}
```

**Cause:** No `Authorization` header provided.

**Solution:** Include Basic authentication header with OAuth2-style credentials:
```bash
curl -H "Authorization: Basic $(echo -n 'your_client_id:your_client_secret' | base64)" ...
```

**Note:** `clientSecret` is optional when `DEPLOYMENT_MODE=community`.

---

### Invalid Credentials

```json
{
  "success": false,
  "error": "Authentication failed: invalid credentials"
}
```

**Cause:** Client credentials are malformed, expired, or revoked.

**Solution:**
- Verify the clientId and clientSecret are correct (check for copy/paste errors)
- Check credential expiration in the AxonFlow dashboard
- Contact support if the credentials should be valid

---

### Invalid User Token

```json
{
  "success": false,
  "error": "Invalid user token"
}
```

**Cause:** The `user_token` JWT is invalid, expired, or malformed.

**Solution:**
- Refresh the user token
- Verify the token is a valid JWT
- Check token expiration

---

### Invalid Client

```json
{
  "success": false,
  "error": "Invalid client"
}
```

**Cause:** The `client_id` is not registered or doesn't exist.

**Solution:**
- Verify the client ID is correct
- Register the client via the AxonFlow dashboard
- Check client configuration in the dashboard

---

### Credentials Invalid or Expired

```json
{
  "success": false,
  "error": "Credentials invalid or expired"
}
```

**Cause:** Client credentials have expired.

**Solution:** Generate new credentials in the AxonFlow dashboard.

## Authorization Errors (403)

### Tenant Mismatch

```json
{
  "success": false,
  "error": "Tenant mismatch"
}
```

**Cause:** User's tenant ID doesn't match the client's tenant ID.

**Solution:**
- Verify the user token is for the correct tenant
- Check client configuration in the dashboard

---

### Client Disabled

```json
{
  "success": false,
  "error": "Client disabled"
}
```

**Cause:** The client application has been disabled.

**Solution:** Enable the client in the AxonFlow dashboard.

---

### Policy Block

```json
{
  "success": false,
  "blocked": true,
  "block_reason": "Query contains PII (SSN detected)",
  "policy_info": {
    "policies_evaluated": ["pii-ssn"],
    "static_checks": ["ssn_pattern"]
  }
}
```

**Cause:** Request blocked by static or dynamic policy.

**Solution:**
- Review the `block_reason` for specific violation
- Modify the query to remove sensitive content
- Request policy exception if legitimate use case

---

### Permission Denied (MCP)

```json
{
  "success": false,
  "error": "Permission denied: service 'app-service' not authorized for connector 'postgres' operation 'delete'"
}
```

**Cause:** Service license doesn't include permission for the requested MCP operation.

**Solution:**
- Check service permissions in license configuration
- Request additional permissions from administrator

---

### Unauthorized Connector Access

```json
{
  "success": false,
  "error": "Unauthorized connector access"
}
```

**Cause:** Tenant doesn't have access to the requested MCP connector.

**Solution:** Request connector access from administrator.

## Validation Errors (400)

### Invalid Request Body

```json
{
  "success": false,
  "error": "Invalid request body"
}
```

**Cause:** Request body is not valid JSON.

**Solution:**
- Validate JSON syntax
- Check for unescaped special characters
- Use a JSON validator

---

### Missing Required Field

```json
{
  "success": false,
  "error": "query field is required"
}
```

**Cause:** Required field missing from request.

**Required fields by endpoint:**
| Endpoint | Required Fields |
|----------|-----------------|
| `/api/request` | `query`, `client_id` |
| `/api/policy/pre-check` | `query`, `client_id` |
| `/api/audit/llm-call` | `context_id`, `client_id`, `provider`, `model`, `token_usage` |
| `/mcp/resources/query` | `client_id`, `connector` |
| `/mcp/tools/execute` | `client_id`, `connector`, `action` |

---

### Invalid or Expired Context

```json
{
  "success": false,
  "error": "Invalid or expired context"
}
```

**Cause:** Gateway Mode context has expired (5 minute TTL) or doesn't exist.

**Solution:**
- Call `/api/policy/pre-check` again to get a new context
- Ensure `/api/audit/llm-call` is called within 5 minutes of pre-check

---

### Invalid Timeout Format

```json
{
  "success": false,
  "error": "Invalid timeout format"
}
```

**Cause:** Timeout string is not a valid Go duration.

**Valid formats:**
- `"5s"` - 5 seconds
- `"30s"` - 30 seconds
- `"1m"` - 1 minute
- `"1m30s"` - 1 minute 30 seconds

## Not Found Errors (404)

### Connector Not Found

```json
{
  "success": false,
  "error": "Connector not found"
}
```

**Cause:** The requested MCP connector doesn't exist.

**Solution:**
- List available connectors: `GET /mcp/connectors`
- Verify connector name spelling
- Check if connector is installed

---

### Policy Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Policy not found"
  }
}
```

**Cause:** Policy ID doesn't exist for this tenant.

**Solution:**
- List policies to verify ID exists
- Check tenant ID is correct

---

### Execution Not Found

```json
{
  "success": false,
  "error": "Execution not found"
}
```

**Cause:** Workflow execution ID doesn't exist.

**Solution:** List executions to get valid IDs.

## Rate Limit Errors (429)

### Rate Limit Exceeded

```json
{
  "success": false,
  "error": "Rate limit exceeded"
}
```

**Headers:**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1705312200
```

**Cause:** Too many requests in the current time window.

**Solution:**
- Wait until `X-RateLimit-Reset` timestamp
- Implement exponential backoff
- Request rate limit increase

**Default Limits:**
| Endpoint | Limit |
|----------|-------|
| Standard | 1000/min |
| Pre-check | 5000/min |
| Bulk ops | 10/min |
| MCP | 500/min |

## Server Errors (500/503)

### Internal Server Error

```json
{
  "success": false,
  "error": "Internal server error"
}
```

**Cause:** Unexpected server error.

**Solution:**
- Retry with exponential backoff
- Check AxonFlow status page
- Contact support with request ID

---

### MCP Registry Not Initialized

```json
{
  "success": false,
  "error": "MCP registry not initialized"
}
```

**Cause:** MCP system not ready (usually during startup).

**Solution:** Wait for service to fully initialize.

---

### Planning Engine Unavailable

```json
{
  "success": false,
  "error": "Multi-Agent Planning not available - Planning Engine not initialized"
}
```

**Cause:** MAP components not initialized (missing LLM configuration).

**Solution:**
- Verify LLM provider is configured
- Check orchestrator logs

---

### Query Execution Failed

```json
{
  "success": false,
  "error": "Query execution failed"
}
```

**Cause:** MCP connector query failed (database error, timeout, etc.).

**Solution:**
- Check connector health: `GET /mcp/connectors/{name}/health`
- Verify query syntax
- Check database connectivity

---

### LLM Routing Failed

```json
{
  "success": false,
  "error": "LLM routing failed: all providers failed"
}
```

**Cause:** All configured LLM providers returned errors.

**Solution:**
- Check provider status: `GET /api/v1/providers/status`
- Verify API keys are configured
- Check provider service status

## Tier Limit Errors (403)

### Policy Limit Exceeded

```json
{
  "error": {
    "code": "POLICY_LIMIT_EXCEEDED",
    "message": "Tenant policy limit reached (20). Upgrade to Evaluation tier for 50 policies.",
    "current_count": 20,
    "limit": 20,
    "tier": "community",
    "upgrade_path": "evaluation"
  }
}
```

**Cause:** You've reached the maximum number of tenant policies for your tier.

**Tier Limits:**
| Tier | Tenant Policy Limit |
|------|---------------------|
| Community | 20 |
| Evaluation | 50 |
| Enterprise | Unlimited |

**Solution:**
- Delete unused policies to free up quota
- Upgrade to Evaluation tier (free) for 50 policies: https://getaxonflow.com/evaluation-license
- Upgrade to Enterprise for unlimited policies

---

### Organization Tier Required

```json
{
  "error": {
    "code": "ORG_TIER_EVALUATION_OR_HIGHER",
    "message": "Organization policies require Evaluation tier or higher. Get a free Evaluation license at https://getaxonflow.com/evaluation-license",
    "tier": "community",
    "required_tier": "evaluation"
  }
}
```

**Cause:** Organization-wide policies are not available in Community tier.

**Tier Limits:**
| Tier | Org Policies |
|------|--------------|
| Community | 0 (not available) |
| Evaluation | 5 |
| Enterprise | Unlimited |

**Solution:**
- Get a free Evaluation license at https://getaxonflow.com/evaluation-license
- Or upgrade to Enterprise for unlimited org policies

---

### Organization Policy Limit Exceeded

```json
{
  "error": {
    "code": "ORG_POLICY_LIMIT_EXCEEDED",
    "message": "Organization policy limit reached (5). Upgrade to Enterprise for unlimited org policies.",
    "current_count": 5,
    "limit": 5,
    "tier": "evaluation",
    "upgrade_path": "enterprise"
  }
}
```

**Cause:** You've reached the maximum number of organization policies for Evaluation tier.

**Tier Limits:**
| Tier | Org Policy Limit |
|------|------------------|
| Community | 0 |
| Evaluation | 5 |
| Enterprise | Unlimited |

**Solution:**
- Delete unused org policies to free up quota
- Upgrade to Enterprise for unlimited org policies

---

### Custom Policy Connector Limit Exceeded

```json
{
  "error": {
    "code": "CONNECTOR_LIMIT_EXCEEDED",
    "message": "Custom policy connector limit reached (2). Upgrade to Evaluation tier for 5 connectors with custom policies.",
    "current_count": 2,
    "limit": 2,
    "tier": "community",
    "upgrade_path": "evaluation"
  }
}
```

**Cause:** You've reached the maximum number of connectors with custom policies for your tier. All connectors can be registered in all tiers, but tenant-level policies (rate limiting, budgets, time/role access) are limited by tier.

**Tier Limits:**
| Tier | Connectors with Custom Policies |
|------|-------------------------------|
| Community | 2 |
| Evaluation | 5 |
| Enterprise | Unlimited |

**Enforcement:** When more connectors are configured than the tier allows, only the first N connectors (in the order listed in `MCP_DYNAMIC_POLICIES_CONNECTORS`) have custom policies enabled. Connectors beyond the limit are registered but without custom policies. Reorder the env var to change priority.

**Solution:**
- Reorder `MCP_DYNAMIC_POLICIES_CONNECTORS` to prioritize connectors that need custom policies
- Upgrade to Evaluation tier (free) for 5 connectors with custom policies
- Upgrade to Enterprise for unlimited connectors with custom policies

---

## Policy-Specific Errors

### PII Detection (Default: Redact)

By default (`PII_ACTION=redact`), PII is flagged for redaction rather than blocked:

```json
{
  "success": true,
  "approved": true,
  "requires_redaction": true,
  "policies": ["pii-ssn"],
  "policy_info": {
    "policies_evaluated": ["pii-ssn", "pii-credit-card", "pii-email"],
    "triggered_policies": ["pii-ssn"],
    "processing_time": "0.8ms"
  }
}
```

### PII Detection Block (When PII_ACTION=block)

When configured with `PII_ACTION=block`, PII triggers a blocking response:

```json
{
  "success": false,
  "blocked": true,
  "block_reason": "PII detected: SSN pattern found in query",
  "policy_info": {
    "policies_evaluated": ["pii-ssn", "pii-credit-card", "pii-email"],
    "triggered_policies": ["pii-ssn"],
    "static_checks": ["ssn_pattern"],
    "processing_time": "0.8ms"
  }
}
```

**PII Types Detected:**
| Type | Pattern | Example Block |
|------|---------|---------------|
| SSN | `XXX-XX-XXXX` | "Show SSN 123-45-6789" |
| Credit Card | 16 digits | "Card 4111111111111111" |
| Email | `user@domain.com` | "Email me at user@example.com" |
| Phone | Various formats | "Call 555-123-4567" |
| IP Address | IPv4 format | "Server at 192.168.1.1" |
| IBAN | International bank | "IBAN DE89370400440532013000" |
| Passport | Country-specific | "Passport AB1234567" |
| DOB | Date patterns | "Born on 01/15/1990" |
| Driver License | State-specific | "License D123456789" |
| Bank Account | ABA routing | "Account 123456789" |

### Dynamic Policy Block

```json
{
  "success": false,
  "error": "Request blocked by dynamic policy",
  "policy_info": {
    "allowed": false,
    "applied_policies": ["high-risk-content"],
    "risk_score": 0.85,
    "required_actions": ["approval_required"]
  }
}
```

**Risk Score Thresholds:**
| Score | Risk Level | Action |
|-------|------------|--------|
| 0.0 - 0.3 | Low | Allow |
| 0.3 - 0.6 | Medium | Allow with audit |
| 0.6 - 0.8 | High | May require approval |
| 0.8 - 1.0 | Critical | Block |

## Troubleshooting Guide

### Debug Checklist

1. **Verify authentication:**
   ```bash
   curl -I https://agent.getaxonflow.com/health \
     -H "Authorization: Basic $(echo -n 'your_client_id:your_client_secret' | base64)"
   ```

2. **Check service health:**
   ```bash
   curl https://agent.getaxonflow.com/health
   curl https://orchestrator.getaxonflow.com/health
   ```

3. **Validate request format:**
   ```bash
   echo '{"query":"test"}' | jq .
   ```

4. **Test with minimal request:**
   ```bash
   curl -X POST https://agent.getaxonflow.com/api/policies/test \
     -H "Content-Type: application/json" \
     -d '{"query": "Hello world"}'
   ```

### Common Issues

| Issue | Likely Cause | Solution |
|-------|--------------|----------|
| 401 on all requests | Missing/invalid credentials | Check `Authorization` header |
| 403 on specific queries | PII detection | Remove sensitive data |
| 503 after deploy | Service starting | Wait 30 seconds |
| Timeout errors | Slow LLM/DB | Increase timeout |
| Empty response | Request blocked | Check `block_reason` |

### Getting Help

If you encounter persistent errors:

1. **Include in support request:**
   - Request ID (if available)
   - Full error response
   - Request payload (sanitized)
   - Timestamp

2. **Contact:**
   - Email: support@getaxonflow.com
   - Slack: #axonflow-support
   - GitHub: https://github.com/getaxonflow/axonflow/issues
