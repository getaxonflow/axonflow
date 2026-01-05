# Provider Restriction Examples for Compliance

Demonstrates using `allowed_providers` in dynamic policies to enforce data residency and compliance requirements by restricting which LLM providers can be used for specific types of requests.

## Use Cases

| Regulation | Requirement | Solution |
|------------|-------------|----------|
| **GDPR** | EU data must stay in EU | Route EU users to Ollama (self-hosted) |
| **HIPAA** | PHI cannot leave organization | Route healthcare data to local LLM only |
| **RBI** | Financial data sovereignty | Route banking queries to India-hosted providers |
| **SOC 2** | Audit trail requirements | Route sensitive queries to audited providers |

## How `allowed_providers` Works

When a dynamic policy matches and has `allowed_providers` in its action config, the LLM router will:

1. Evaluate the policy conditions against the request
2. If matched, filter available providers to only those in `allowed_providers`
3. Route the request to a healthy provider from that filtered list
4. If no allowed providers are healthy, return an error (no fallback to disallowed providers)

```json
{
  "name": "gdpr-eu-data-sovereignty",
  "type": "content",
  "category": "dynamic-compliance",
  "conditions": [
    { "field": "user_region", "operator": "equals", "value": "EU" }
  ],
  "actions": [
    { "type": "route", "config": { "allowed_providers": ["ollama", "azure-eu"] } }
  ]
}
```

## SDK Methods

| Method | Description |
|--------|-------------|
| `CreateDynamicPolicy()` | Create policy with `allowed_providers` |
| `UpdateDynamicPolicy()` | Update provider restrictions |
| `GetEffectiveDynamicPolicies()` | See which policies apply to a tenant |

## Quick Start

### Prerequisites

1. Start AxonFlow services:
   ```bash
   docker compose up -d
   ```

2. For local LLM routing, start Ollama:
   ```bash
   docker compose --profile local-llm up -d
   ollama pull llama3.2
   ```

3. Set environment variables:
   ```bash
   export AXONFLOW_ENDPOINT="http://localhost:8080"
   export AXONFLOW_LICENSE_KEY="your-license-key"
   export AXONFLOW_CLIENT_ID="demo-tenant"
   ```

### Run Examples

**Go:**
```bash
cd go
go run main.go
```

**Python:**
```bash
cd python
pip install axonflow
python main.py
```

**TypeScript:**
```bash
cd typescript
npm install @axonflow/sdk
npx ts-node index.ts
```

**Java:**
```bash
cd java
mvn exec:java -Dexec.mainClass="com.example.CompliancePolicyExample"
```

## Example Scenarios

### 1. GDPR - EU Data Sovereignty

Ensures EU user data never leaves EU-hosted infrastructure:

```go
policy := axonflow.CreateDynamicPolicyRequest{
    Name:        "gdpr-eu-data-sovereignty",
    Description: "Route EU users to EU-hosted LLMs only",
    Type:        "content",
    Category:    "dynamic-compliance",
    Conditions: []axonflow.DynamicPolicyCondition{
        {Field: "user_region", Operator: "equals", Value: "EU"},
    },
    Actions: []axonflow.DynamicPolicyAction{
        {Type: "route", Config: map[string]interface{}{"allowed_providers": []string{"ollama", "azure-eu"}}},
    },
    Enabled: true,
}
```

### 2. HIPAA - Healthcare Data Protection

Routes PHI queries to self-hosted models only:

```python
from axonflow import DynamicPolicyAction, DynamicPolicyCondition

policy = client.create_dynamic_policy(CreateDynamicPolicyRequest(
    name="hipaa-phi-protection",
    description="Route PHI queries to local LLM only",
    type="content",
    category="dynamic-compliance",
    conditions=[
        DynamicPolicyCondition(field="request_type", operator="equals", value="healthcare"),
        DynamicPolicyCondition(field="contains_phi", operator="equals", value=True),
    ],
    actions=[DynamicPolicyAction(type="route", config={"allowed_providers": ["ollama"]})],
    enabled=True,
))
```

### 3. RBI - India Financial Data Sovereignty

Ensures banking data stays within India:

```typescript
const policy = await client.createDynamicPolicy({
    name: "rbi-financial-data-sovereignty",
    description: "Route banking queries to India-hosted providers",
    type: "content",
    category: "dynamic-compliance",
    conditions: [
        { field: "request_type", operator: "equals", value: "banking" },
        { field: "user_region", operator: "equals", value: "IN" },
    ],
    actions: [
        { type: "route", config: { allowed_providers: ["azure-india", "ollama"] } },
    ],
    enabled: true,
});
```

## Expected Output

```
=== Compliance Policy Examples ===

1. Creating GDPR policy for EU data sovereignty...
   Created: gdpr-eu-data-sovereignty (ID: pol_gdpr123)
   Allowed providers: [ollama, azure-eu]

2. Creating HIPAA policy for PHI protection...
   Created: hipaa-phi-protection (ID: pol_hipaa456)
   Allowed providers: [ollama]

3. Creating RBI policy for financial data...
   Created: rbi-financial-data-sovereignty (ID: pol_rbi789)
   Allowed providers: [azure-india, ollama]

4. Listing all compliance policies...
   Found 3 compliance policies with provider restrictions

5. Testing policy evaluation...
   EU user query -> Routed to: ollama (GDPR compliant)
   Healthcare query -> Routed to: ollama (HIPAA compliant)
   Banking query (IN) -> Routed to: azure-india (RBI compliant)

6. Cleaning up test policies...
   All test policies deleted

=== Compliance Policy Examples Complete ===
```

## Related Examples

- [Dynamic Policies](../) - Basic dynamic policy CRUD
- [LLM Routing](../../llm-routing/) - Provider routing configuration
- [Static Policies](../../static-policies/) - Pattern-based policies
