# Policy Management Examples (Python)

Examples demonstrating policy CRUD operations using the AxonFlow Python SDK.

## Prerequisites

- Python 3.10+
- AxonFlow running locally or endpoint URL
- Python SDK installed

## Setup

```bash
pip install -r requirements.txt
```

## Environment Variables

```bash
export AXONFLOW_ENDPOINT=http://localhost:8080
# For Enterprise examples:
export AXONFLOW_LICENSE_KEY=your-license-key
```

Or copy the `.env.example` file:

```bash
cp .env.example .env
# Edit .env with your configuration
```

## Examples

| File | Description |
|------|-------------|
| `create_custom_policy.py` | Create a custom tenant-tier policy |
| `list_and_filter.py` | List policies with filters |
| `test_pattern.py` | Test regex patterns before saving |

## Run Examples

```bash
python create_custom_policy.py
python list_and_filter.py
python test_pattern.py
```

## SDK Methods Used

### Static Policies

```python
from axonflow import (
    AxonFlow,
    CreateStaticPolicyRequest,
    ListStaticPoliciesOptions,
    PolicyCategory,
    PolicyTier,
)

async with AxonFlow(endpoint="http://localhost:8080") as client:
    # List policies with filters
    policies = await client.list_static_policies(
        ListStaticPoliciesOptions(
            category=PolicyCategory.SECURITY_SQLI,
            tier=PolicyTier.SYSTEM,
            enabled=True,
            limit=20,
            sort_by="severity",
            sort_order="desc",
        )
    )

    # Create a new policy
    policy = await client.create_static_policy(
        CreateStaticPolicyRequest(
            name="My Custom Policy",
            description="Detects sensitive patterns",
            category=PolicyCategory.PII_GLOBAL,
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            severity=8,
            enabled=True,
        )
    )

    # Get a specific policy
    retrieved = await client.get_static_policy(policy_id)

    # Update a policy
    updated = await client.update_static_policy(
        policy_id,
        UpdateStaticPolicyRequest(enabled=False, severity=9)
    )

    # Delete a policy
    await client.delete_static_policy(policy_id)

    # Get effective policies (with tier inheritance)
    effective = await client.get_effective_static_policies(
        EffectivePoliciesOptions(category=PolicyCategory.SECURITY_SQLI)
    )

    # Test a pattern before creating a policy
    result = await client.test_pattern(
        r"\b\d{3}-\d{2}-\d{4}\b",
        ["123-45-6789", "no match here"]
    )
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
