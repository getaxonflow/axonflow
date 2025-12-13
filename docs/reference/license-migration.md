# License Migration Guide: V1 to V2

This guide explains how to migrate from the deprecated V1 license format to the current V2 format.

## Overview

AxonFlow uses license keys to validate your subscription tier and organization. As of PR #167, we have transitioned from V1 to V2 license format for improved security and features.

### Version Comparison

| Feature | V1 (Deprecated) | V2 (Current) |
|---------|----------------|--------------|
| Format | `AXON-TIER-ORG-EXPIRY-SIG` | `AXON-V2-xxx-yyy` |
| Security | Basic signature | Enhanced cryptographic signature |
| Node Limits | Not enforced | Enforced per tier |
| API Rate Limits | Not enforced | Enforced per tier |
| Auto-Renewal | Manual | AWS Marketplace integrated |

## Identifying Your License Version

### V1 License Format (Deprecated)

```
AXON-PILOT-acme-20251231-abc123
     ├──── ├──── ├──────── └───── Signature
     │     │     └──────────────── Expiry (YYYYMMDD)
     │     └────────────────────── Organization ID
     └──────────────────────────── Tier (PILOT/GROWTH/ENTERPRISE)
```

### V2 License Format (Current)

```
AXON-V2-a1b2c3d4-e5f6g7h8
        └─────── └─────── License components (encoded)
```

V2 licenses are automatically generated when you:
- Subscribe via AWS Marketplace
- Deploy via CloudFormation
- Contact sales for enterprise licenses

## Migration Steps

### Step 1: Identify Your Deployment Type

**AWS Marketplace Customers:**
- V2 licenses are automatically provisioned
- No action required if deployed after November 2025

**Self-Hosted Customers:**
- Contact sales@getaxonflow.com for V2 license
- Provide your organization ID and current tier

### Step 2: Update Your Configuration

#### Environment Variable

Replace your existing license key:

```bash
# Old (V1)
AXONFLOW_LICENSE_KEY=AXON-PILOT-acme-20251231-abc123

# New (V2)
AXONFLOW_LICENSE_KEY=AXON-V2-a1b2c3d4-e5f6g7h8
```

#### AWS Secrets Manager

If using Secrets Manager:

```bash
aws secretsmanager update-secret \
  --secret-id axonflow/license \
  --secret-string "AXON-V2-your-new-license-key"
```

#### CloudFormation

Update your stack parameter:

```yaml
Parameters:
  LicenseKey:
    Type: String
    Default: "AXON-V2-your-new-license-key"
```

### Step 3: Verify the Migration

After updating, verify your license is active:

```bash
# Check license status via health endpoint
curl -s https://YOUR_AGENT_ENDPOINT/health | jq '.license'

# Expected output
{
  "valid": true,
  "version": "v2",
  "tier": "PROFESSIONAL",
  "organization": "your-org-id",
  "expires": "2026-12-31T23:59:59Z"
}
```

## Troubleshooting

### Error: "V1 license format is deprecated"

**Cause:** You're using an old V1 format license.

**Solution:**
1. Contact sales@getaxonflow.com with your organization ID
2. Request a V2 license key
3. Update your configuration as shown above

### Error: "License validation failed"

**Cause:** The V2 license key is malformed or expired.

**Solution:**
1. Verify the license key format starts with `AXON-V2-`
2. Check for copy/paste errors (extra spaces, truncation)
3. Verify the license hasn't expired
4. For AWS Marketplace: Check your subscription is active

### Error: "Organization ID mismatch"

**Cause:** License was issued for a different organization.

**Solution:**
1. Verify `AXONFLOW_ORG_ID` matches your license
2. Contact sales if organization ID changed

## Getting a V2 License

### AWS Marketplace Customers

V2 licenses are automatically generated when you subscribe. Check your deployment:

1. Go to AWS Marketplace → Your subscriptions
2. Find AxonFlow subscription
3. Click "Manage" → View configuration
4. License key is in CloudFormation outputs

### Self-Hosted Customers

Contact us for a V2 license:

- **Email:** sales@getaxonflow.com
- **Subject:** V2 License Migration Request
- **Include:**
  - Organization ID
  - Current license tier
  - Expiry date preference
  - Number of nodes required

## License Tier Comparison

| Tier | Nodes | Monthly Requests | Price |
|------|-------|-----------------|-------|
| Pilot | 5 | 50,000 | $7,000/month |
| Professional | 10 | 500,000 | $20,000/month |
| Enterprise | Unlimited | Unlimited | Contact Sales |

## FAQ

### Q: Will my V1 license stop working?

**A:** V1 licenses will continue to work but are deprecated. We recommend migrating to V2 for:
- Better security
- Access to new features
- Node limit enforcement
- AWS Marketplace integration

### Q: Is there a cost to migrate?

**A:** No. Migration to V2 is free. Your tier and pricing remain unchanged.

### Q: How long does migration take?

**A:** For self-hosted:
- License generation: 1 business day
- Configuration update: 5 minutes

For AWS Marketplace:
- Automatic - no action required

### Q: What happens to my data during migration?

**A:** Nothing. License migration is a configuration change only. No data is affected.

## Related

- [Getting Started](/docs/getting-started.md)
- [CloudFormation Deployment](/docs/deployment/cloudformation.md)
- [AWS Marketplace](/docs/deployment/aws-marketplace.md)

## Support

For migration assistance:
- **Email:** support@getaxonflow.com
- **Slack:** #axonflow-support (Enterprise customers)
- **Documentation:** https://docs.getaxonflow.com
