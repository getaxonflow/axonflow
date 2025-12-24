# Policy Management Examples (Java)

Examples demonstrating policy CRUD operations using the AxonFlow Java SDK.

## Prerequisites

- Java 17+
- Maven 3.8+
- AxonFlow running locally or endpoint URL
- Java SDK installed

## Setup

```bash
mvn compile
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
| `CreateCustomPolicy.java` | Create a custom tenant-tier policy |
| `ListAndFilter.java` | List policies with filters |
| `TestPattern.java` | Test regex patterns before saving |

## Run Examples

```bash
# Run individual examples
mvn compile exec:java -Pcreate
mvn compile exec:java -Plist
mvn compile exec:java -Ptest-pattern

# Or specify the main class directly
mvn compile exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.CreateCustomPolicy"
mvn compile exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.ListAndFilter"
mvn compile exec:java -Dexec.mainClass="com.getaxonflow.examples.policies.TestPattern"
```

## SDK Methods Used

### Static Policies

```java
import com.getaxonflow.sdk.AxonFlow;
import com.getaxonflow.sdk.AxonFlowConfig;
import com.getaxonflow.sdk.types.policies.PolicyTypes.*;

AxonFlowConfig config = AxonFlowConfig.builder()
    .endpoint("http://localhost:8080")
    .build();
AxonFlow axonflow = new AxonFlow(config);

// List policies with filters
ListStaticPoliciesOptions options = ListStaticPoliciesOptions.builder()
    .category(PolicyCategory.SECURITY_SQLI)
    .tier(PolicyTier.SYSTEM)
    .enabled(true)
    .limit(20)
    .sortBy("severity")
    .sortOrder("desc")
    .build();
List<StaticPolicy> policies = axonflow.listStaticPolicies(options);

// Create a new policy
CreateStaticPolicyRequest request = CreateStaticPolicyRequest.builder()
    .name("My Custom Policy")
    .description("Detects sensitive patterns")
    .category(PolicyCategory.PII_GLOBAL)
    .pattern("\\b\\d{3}-\\d{2}-\\d{4}\\b")
    .severity(8)
    .enabled(true)
    .build();
StaticPolicy policy = axonflow.createStaticPolicy(request);

// Get a specific policy
StaticPolicy retrieved = axonflow.getStaticPolicy(policyId);

// Update a policy
UpdateStaticPolicyRequest updateReq = UpdateStaticPolicyRequest.builder()
    .enabled(false)
    .severity(9)
    .build();
StaticPolicy updated = axonflow.updateStaticPolicy(policyId, updateReq);

// Delete a policy
axonflow.deleteStaticPolicy(policyId);

// Get effective policies (with tier inheritance)
EffectivePoliciesOptions effOptions = EffectivePoliciesOptions.builder()
    .category(PolicyCategory.SECURITY_SQLI)
    .build();
List<StaticPolicy> effective = axonflow.getEffectiveStaticPolicies(effOptions);

// Test a pattern before creating a policy
TestPatternResult result = axonflow.testPattern(
    "\\b\\d{3}-\\d{2}-\\d{4}\\b",
    Arrays.asList("123-45-6789", "no match here")
);
```

## Policy Categories

| Category | Description |
|----------|-------------|
| `PolicyCategory.SECURITY_SQLI` | SQL injection detection |
| `PolicyCategory.SECURITY_ADMIN` | Admin/privilege escalation |
| `PolicyCategory.PII_GLOBAL` | Global PII patterns |
| `PolicyCategory.PII_US` | US-specific PII (SSN, etc.) |
| `PolicyCategory.PII_EU` | EU-specific PII (GDPR) |
| `PolicyCategory.PII_INDIA` | India-specific PII (Aadhaar, PAN) |
| `PolicyCategory.CUSTOM` | Custom user-defined policies |

## Policy Tiers

| Tier | Description |
|------|-------------|
| `PolicyTier.SYSTEM` | Platform-wide (read-only) |
| `PolicyTier.ORGANIZATION` | Organization-wide (Enterprise) |
| `PolicyTier.TENANT` | Tenant-specific (customizable) |

## Next Steps

- [Enterprise Examples](../../../ee/examples/policies/) - Organization policies, overrides
- [Industry Examples](../../../ee/examples/industry/) - Banking, Healthcare patterns
