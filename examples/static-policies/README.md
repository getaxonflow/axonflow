# Static Policy Management Example

This example demonstrates **ALL static policy SDK methods** using the AxonFlow SDK.

## SDK Methods Demonstrated

| # | Method | Description |
|---|--------|-------------|
| 1 | `listStaticPolicies()` | List all static policies with optional filtering |
| 2 | `listStaticPolicies(category)` | Filter policies by category |
| 3 | `createStaticPolicy()` | Create a new custom static policy |
| 4 | `getStaticPolicy()` | Retrieve a policy by ID |
| 5 | `testPattern()` | Test a regex pattern against sample inputs |
| 6 | `updateStaticPolicy()` | Update an existing policy |
| 7 | `getStaticPolicyVersions()` | Get version history for a policy |
| 8 | `toggleStaticPolicy()` | Enable or disable a policy |
| 9 | `getEffectiveStaticPolicies()` | Get policies with tier inheritance applied |
| 10 | `deleteStaticPolicy()` | Delete a policy |

## Prerequisites

```bash
# Start AxonFlow
cd /path/to/axonflow-enterprise
docker compose up -d

# Verify services are healthy
curl http://localhost:8080/health
curl http://localhost:8081/health
```

## Running the Examples

### Python

```bash
cd python
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install axonflow
python main.py
```

### Go

```bash
cd go
go mod tidy
go run main.go
```

### TypeScript

```bash
cd typescript
npm install
npx ts-node index.ts
```

### Java

```bash
cd java
mvn compile exec:java
```

## Expected Output

```
AxonFlow Static Policy Management - <Language> SDK
===================================================

1. listStaticPolicies - Listing all static policies...
   Found X policies
   - policy-name-1: security-sqli (enabled)
   - policy-name-2: pii-global (enabled)
   ...

2. listStaticPolicies - Filtering by category...
   Found X SQL injection policies

3. createStaticPolicy - Creating a custom policy...
   Created: demo-custom-policy-1704384000
   ID: abc123
   Category: custom
   Action: warn

4. getStaticPolicy - Retrieving policy by ID...
   Retrieved: demo-custom-policy-1704384000
   Pattern: (?i)test_secret_\d+
   Enabled: true

5. testPattern - Testing regex pattern...
   Pattern valid: true
   Match results:
     [MATCH] test_secret_123
     [NO MATCH] test_secret_abc
     [MATCH] TEST_SECRET_999
     ...

... (continues through all 10 methods)

===================================================
All 10 Static Policy SDK methods tested!
```

## Policy Categories

| Category | Description |
|----------|-------------|
| `security-sqli` | SQL injection detection |
| `security-admin` | Admin command detection |
| `pii-global` | Global PII patterns |
| `pii-us` | US-specific PII (SSN, etc.) |
| `pii-eu` | EU-specific PII (IBAN, etc.) |
| `pii-india` | India-specific PII (Aadhaar, etc.) |
| `custom` | User-defined policies |

## Policy Tiers

| Tier | Description |
|------|-------------|
| `system` | AxonFlow-managed, read-only |
| `organization` | Organization-wide (Enterprise) |
| `tenant` | Tenant-specific (default for custom) |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AXONFLOW_AGENT_URL` | `http://localhost:8080` | Agent URL |
| `AXONFLOW_ORCHESTRATOR_URL` | `http://localhost:8081` | Orchestrator URL |
| `AXONFLOW_CLIENT_ID` | `demo-client` | Client ID |
| `AXONFLOW_CLIENT_SECRET` | `demo-secret` | Client secret |

## Related Examples

- [Dynamic Policies](../dynamic-policies/) - Dynamic policy management
- [Policy Overrides](../../ee/examples/policies/overrides/) - Enterprise policy overrides
- [Policies CRUD](../policies/) - HTTP API examples (deprecated, use SDK)

## Troubleshooting

### "Policy not found" error
Ensure the policy ID is correct and the policy exists. Policies are deleted when the example completes.

### "Version history not available"
`getStaticPolicyVersions()` may require an Enterprise license for full functionality.

### "Cannot create policy" error
Ensure you have appropriate permissions. Custom policies require tenant or organization tier.
