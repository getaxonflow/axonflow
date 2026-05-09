# Evaluation Tier Examples

> **Tier compatibility:** Community / Evaluation. These examples work without any license
> (Community mode) and with a free Evaluation license. No paid license required.

These examples demonstrate and test the three-tier licensing model in AxonFlow:

| Tier | License Required | Tenant Policies | Org Policies | Custom Policy Connectors* | SSE Connections | Audit Retention |
|------|------------------|-----------------|--------------|---------------------------|-----------------|-----------------|
| **Community** | No | 20 | 0 | 2 | 5 | 3 days |
| **Evaluation** | Free license | 50 | 5 | 5 | 25 | 14 days |
| **Enterprise** | Paid license | Unlimited | Unlimited | Unlimited | Unlimited | 10 years |

\* **Custom Policy Connectors** = connectors with tenant/org-level custom policies (rate limiting, budgets, time/role-based access). Connector *registration* is unlimited in all tiers; only the number of connectors that can have custom policies applied is capped.

## What These Examples Test

1. **Tier Detection** - Verify the correct license tier is detected
2. **Tenant Policy Limits** - Test that policy limits are enforced per tier
3. **Organization Policy Access** - Community cannot create org policies; Evaluation allows up to 5
4. **SSE Connection Limits** - Verify per-tenant SSE streaming connection limits (5/25/unlimited)
5. **Upgrade Path Messages** - Error messages include links to upgrade

## Running the Examples

### Prerequisites

```bash
# Start AxonFlow
docker compose up -d
```

### Community Mode (No License)

```bash
# Unset any license key
unset AXONFLOW_LICENSE_KEY

# Run the test
cd python && python test_tier_limits.py
```

### Evaluation Mode

```bash
# Set an Evaluation tier license key
export AXONFLOW_LICENSE_KEY="<your-evaluation-license-key>"

# Run the test
cd python && python test_tier_limits.py
```

To get a free Evaluation license: https://getaxonflow.com/evaluation-license

### Enterprise Mode

```bash
# Set an Enterprise license key
export AXONFLOW_LICENSE_KEY="<your-enterprise-license-key>"

# Run the test
cd python && python test_tier_limits.py
```

## Available Examples

- **Python** (`python/`) - Uses `axonflow` SDK
- **Go** (`go/`) - Uses `github.com/getaxonflow/axonflow-sdk-go/v8`
- **Java** (`java/`) - Uses `com.getaxonflow:axonflow-sdk`
- **TypeScript** (`typescript/`) - Uses `@axonflow/sdk`
- **HTTP** (`http/`) - Direct HTTP API calls (curl)

## Expected Output

### Community Mode
```
1. Testing Tier Detection
   ✓ PASS: Platform is healthy

2. Testing Tenant Policy Limits
   Current policy count: 0
   Expected limit for community: 20
   ✓ PASS: Policy creation succeeded

3. Testing Organization Policy Access
   ✓ PASS: Community tier correctly blocked org policy creation
   ✓ PASS: Error message includes upgrade path to Evaluation

✓ All tests passed!
```

### Evaluation Mode
```
1. Testing Tier Detection
   ✓ PASS: Platform is healthy

2. Testing Tenant Policy Limits
   Current policy count: 0
   Expected limit for evaluation: 50
   ✓ PASS: Policy creation succeeded

3. Testing Organization Policy Access
   ✓ PASS: Evaluation tier can create org policies

✓ All tests passed!
```

## Error Codes

The examples verify these tier-related error codes:

| Error Code | Meaning | Solution |
|------------|---------|----------|
| `POLICY_LIMIT_EXCEEDED` | Tenant policy limit reached | Upgrade tier or delete policies |
| `ORG_TIER_EVALUATION_OR_HIGHER` | Org policies require Evaluation+ | Get free Evaluation license |
| `ORG_POLICY_LIMIT_EXCEEDED` | Org policy limit reached (Evaluation) | Upgrade to Enterprise |
| `CONNECTOR_LIMIT_EXCEEDED` | Custom policy connector limit reached | Upgrade tier |

## Graceful Degradation

When an Evaluation license expires:
- Services continue running (no outage)
- Limits degrade to Community tier (20/0/2/3)
- Existing data is preserved
- Clear messaging: "License expired. Renew at [link]"

## Related Documentation

- [Three-Tier Feature Matrix](../../technical-docs/COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md)
- [License Architecture](../../technical-docs/LICENSE_ARCHITECTURE.md)
- [Error Codes Reference](../../docs/api/error-codes.md)
- [Getting Started Guide](../../docs/getting-started.md)
