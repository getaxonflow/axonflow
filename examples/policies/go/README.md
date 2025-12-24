# Policy Management Examples (Go)

Examples demonstrating policy CRUD operations using the AxonFlow Go SDK.

## Prerequisites

- Go 1.21+
- AxonFlow running locally or endpoint URL
- Go SDK installed

## Setup

```bash
# Install SDK from feature branch
go get github.com/getaxonflow/axonflow-sdk-go@feat/policy-crud
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
| `create_custom_policy.go` | Create a custom tenant-tier policy |
| `list_and_filter.go` | List policies with filters |
| `test_pattern.go` | Test regex patterns before saving |

## Run Examples

```bash
go run create_custom_policy.go
go run list_and_filter.go
go run test_pattern.go
```

## SDK Methods Used

### Static Policies

```go
import axonflow "github.com/getaxonflow/axonflow-sdk-go"

client := axonflow.NewClient("http://localhost:8080")

// List policies with filters
enabled := true
policies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
    Category: axonflow.CategorySecuritySQLI,
    Tier:     axonflow.TierSystem,
    Enabled:  &enabled,
    Limit:    &limit,
    SortBy:   "severity",
    SortOrder: "desc",
})

// Create a new policy
policy, err := client.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
    Name:        "My Custom Policy",
    Description: "Detects sensitive patterns",
    Category:    axonflow.CategoryPIIGlobal,
    Pattern:     `\b\d{3}-\d{2}-\d{4}\b`,
    Severity:    8,
    Enabled:     true,
})

// Get a specific policy
retrieved, err := client.GetStaticPolicy(policyID)

// Update a policy
updated, err := client.UpdateStaticPolicy(policyID, &axonflow.UpdateStaticPolicyRequest{
    Enabled:  false,
    Severity: 9,
})

// Delete a policy
err := client.DeleteStaticPolicy(policyID)

// Get effective policies (with tier inheritance)
effective, err := client.GetEffectiveStaticPolicies(&axonflow.EffectivePoliciesOptions{
    Category: axonflow.CategorySecuritySQLI,
})

// Test a pattern before creating a policy
result, err := client.TestPattern(
    `\b\d{3}-\d{2}-\d{4}\b`,
    []string{"123-45-6789", "no match here"},
)
```

## Policy Categories

| Category | Description |
|----------|-------------|
| `CategorySecuritySQLI` | SQL injection detection |
| `CategorySecurityAdmin` | Admin/privilege escalation |
| `CategoryPIIGlobal` | Global PII patterns |
| `CategoryPIIUS` | US-specific PII (SSN, etc.) |
| `CategoryPIIEU` | EU-specific PII (GDPR) |
| `CategoryPIIIndia` | India-specific PII (Aadhaar, PAN) |
| `CategoryCustom` | Custom user-defined policies |

## Policy Tiers

| Tier | Description |
|------|-------------|
| `TierSystem` | Platform-wide (read-only) |
| `TierOrganization` | Organization-wide (Enterprise) |
| `TierTenant` | Tenant-specific (customizable) |

## Next Steps

- [Enterprise Examples](../../../ee/examples/policies/) - Organization policies, overrides
- [Industry Examples](../../../ee/examples/industry/) - Banking, Healthcare patterns
