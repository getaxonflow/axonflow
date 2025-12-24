# Policy Management Examples (TypeScript)

Examples demonstrating policy CRUD operations using the AxonFlow TypeScript SDK.

## Prerequisites

- Node.js 18+
- AxonFlow running locally or endpoint URL
- TypeScript SDK installed

## Setup

```bash
npm install
```

## Environment Variables

```bash
export AXONFLOW_ENDPOINT=http://localhost:8080
# For Enterprise examples:
export AXONFLOW_LICENSE_KEY=your-license-key
```

## Examples

| File | Description |
|------|-------------|
| `create-custom-policy.ts` | Create a custom tenant-tier policy |
| `list-and-filter.ts` | List policies with filters |
| `test-pattern.ts` | Test regex patterns before saving |

## Run Examples

```bash
# Run individual examples
npm run create
npm run list
npm run test-pattern

# Run all examples
npm run all
```

Or run directly:

```bash
npx tsx create-custom-policy.ts
npx tsx list-and-filter.ts
npx tsx test-pattern.ts
```

## SDK Methods Used

### Static Policies

```typescript
// List policies with filters
const policies = await client.listStaticPolicies({
  category: 'security-sqli',
  tier: 'system',
  enabled: true,
  limit: 20,
  sortBy: 'severity',
  sortOrder: 'desc',
});

// Create a new policy
const policy = await client.createStaticPolicy({
  name: 'My Custom Policy',
  description: 'Detects sensitive patterns',
  category: 'pii-global',
  pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
  severity: 8,
  enabled: true,
  action: 'block',
});

// Get a specific policy
const retrieved = await client.getStaticPolicy(policyId);

// Update a policy
const updated = await client.updateStaticPolicy(policyId, {
  enabled: false,
  severity: 9,
});

// Delete a policy
await client.deleteStaticPolicy(policyId);

// Get effective policies (with tier inheritance)
const effective = await client.getEffectiveStaticPolicies({
  category: 'security-sqli',
});

// Test a pattern before creating a policy
const result = await client.testPattern(
  '\\b\\d{3}-\\d{2}-\\d{4}\\b',
  ['123-45-6789', 'no match here']
);
```

## Policy Categories

| Category | Description |
|----------|-------------|
| `security-sqli` | SQL injection detection |
| `security-admin` | Admin/privilege escalation |
| `pii-global` | Global PII patterns |
| `pii-us` | US-specific PII (SSN, etc.) |
| `pii-eu` | EU-specific PII (GDPR) |
| `pii-india` | India-specific PII (Aadhaar, PAN) |
| `custom` | Custom user-defined policies |

## Policy Tiers

| Tier | Description |
|------|-------------|
| `system` | Platform-wide (read-only) |
| `organization` | Organization-wide (Enterprise) |
| `tenant` | Tenant-specific (customizable) |

## Next Steps

- [Enterprise Examples](../../../ee/examples/policies/) - Organization policies, overrides
- [Industry Examples](../../../ee/examples/industry/) - Banking, Healthcare patterns
