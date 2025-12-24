"""
AxonFlow Policy Management - List and Filter Policies

This example demonstrates how to:
- List all static policies
- Filter policies by category, tier, and status
- Get effective policies with tier inheritance
"""

import asyncio
import os
from collections import Counter

from axonflow import (
    AxonFlow,
    EffectivePoliciesOptions,
    ListStaticPoliciesOptions,
    PolicyCategory,
    PolicyTier,
)


async def main() -> None:
    """List and filter policies."""
    client = AxonFlow(
        agent_url=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",  # Used as tenant ID
        client_secret="test-secret",  # Not validated in Community mode
    )

    print("AxonFlow Policy Management - List and Filter")
    print("=" * 60)

    try:
        # 1. List all policies
        print("\n1. Listing all policies...")

        all_policies = await client.list_static_policies()
        print(f"   Total: {len(all_policies)} policies")

        # Group by category for summary
        by_category = Counter(str(p.category.value) for p in all_policies)
        print("\n   By category:")
        for cat, count in by_category.items():
            print(f"     {cat}: {count}")

        # 2. Filter by category - SQL Injection policies
        print("\n2. Filtering by category (security-sqli)...")

        sqli_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(category=PolicyCategory.SECURITY_SQLI)
        )
        print(f"   Found: {len(sqli_policies)} SQLi policies")

        # Show first 3
        for p in sqli_policies[:3]:
            print(f"     - {p.name} (severity: {p.severity})")
        if len(sqli_policies) > 3:
            print(f"     ... and {len(sqli_policies) - 3} more")

        # 3. Filter by tier - System policies
        print("\n3. Filtering by tier (system)...")

        system_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(tier=PolicyTier.SYSTEM)
        )
        print(f"   Found: {len(system_policies)} system policies")

        # 4. Filter by enabled status
        print("\n4. Filtering by enabled status...")

        enabled_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(enabled=True)
        )
        disabled_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(enabled=False)
        )

        print(f"   Enabled: {len(enabled_policies)}")
        print(f"   Disabled: {len(disabled_policies)}")

        # 5. Combine filters
        print("\n5. Combining filters (enabled PII policies)...")

        pii_enabled = await client.list_static_policies(
            ListStaticPoliciesOptions(
                category=PolicyCategory.PII_GLOBAL,
                enabled=True,
            )
        )
        print(f"   Found: {len(pii_enabled)} enabled PII policies")

        for p in pii_enabled[:5]:
            pattern_preview = p.pattern[:40] + "..." if len(p.pattern) > 40 else p.pattern
            print(f"     - {p.name}: {pattern_preview}")

        # 6. Get effective policies (includes tier inheritance)
        print("\n6. Getting effective policies...")

        effective = await client.get_effective_static_policies()
        print(f"   Effective total: {len(effective)} policies")

        # Group by tier
        by_tier = Counter(str(p.tier.value) for p in effective)
        print("\n   By tier (effective):")
        for tier, count in by_tier.items():
            print(f"     {tier}: {count}")

        # 7. Pagination example
        print("\n7. Pagination example...")

        page1 = await client.list_static_policies(
            ListStaticPoliciesOptions(limit=5, offset=0)
        )
        page2 = await client.list_static_policies(
            ListStaticPoliciesOptions(limit=5, offset=5)
        )

        print(f"   Page 1: {len(page1)} policies")
        print(f"   Page 2: {len(page2)} policies")

        # 8. Sorting
        print("\n8. Sorting by severity (descending)...")

        by_severity = await client.list_static_policies(
            ListStaticPoliciesOptions(
                sort_by="severity",
                sort_order="desc",
                limit=5,
            )
        )

        print("   Top 5 by severity:")
        for p in by_severity:
            print(f"     [{p.severity}] {p.name}")

        print("\n" + "=" * 60)
        print("Example completed successfully!")

    except Exception as e:
        print(f"\nError: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
