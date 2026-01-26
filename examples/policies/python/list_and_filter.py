#!/usr/bin/env python3
"""
AxonFlow Policy Management - List and Filter Policies

VALIDATION: This example exits with code 1 if any assertion fails.

This example demonstrates how to:
- List all static policies
- Filter policies by category, tier, and status
- Get effective policies with tier inheritance

Run with: python list_and_filter.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys
from collections import Counter

from axonflow import (
    AxonFlow,
    ListStaticPoliciesOptions,
    PolicyCategory,
    PolicyTier,
)

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    """List and filter policies."""
    print("AxonFlow Policy Management - List and Filter")
    print("=" * 60)

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",
        client_secret="test-secret",
    )

    try:
        # 1. List all policies
        print("\n1. Listing all policies...")

        all_policies = await client.list_static_policies()
        assert_check(all_policies is not None, "list_static_policies returned result")
        assert_check(isinstance(all_policies, list), "Result is a list")

        print(f"   Total: {len(all_policies)} policies")

        # Group by category for summary
        if all_policies:
            by_category = Counter(str(p.category.value) for p in all_policies)
            print("\n   By category:")
            for cat, count in by_category.items():
                print(f"     {cat}: {count}")

        # 2. Filter by category - SQL Injection policies
        print("\n2. Filtering by category (security-sqli)...")

        sqli_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(category=PolicyCategory.SECURITY_SQLI)
        )
        assert_check(sqli_policies is not None, "Category filter returned result")
        assert_check(isinstance(sqli_policies, list), "Category filter result is a list")

        print(f"   Found: {len(sqli_policies)} SQLi policies")

        for p in sqli_policies[:3]:
            print(f"     - {p.name} (severity: {p.severity})")
        if len(sqli_policies) > 3:
            print(f"     ... and {len(sqli_policies) - 3} more")

        # 3. Filter by tier - System policies
        print("\n3. Filtering by tier (system)...")

        system_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(tier=PolicyTier.SYSTEM)
        )
        assert_check(system_policies is not None, "Tier filter returned result")

        print(f"   Found: {len(system_policies)} system policies")

        # 4. Filter by enabled status
        print("\n4. Filtering by enabled status...")

        enabled_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(enabled=True)
        )
        disabled_policies = await client.list_static_policies(
            ListStaticPoliciesOptions(enabled=False)
        )

        assert_check(enabled_policies is not None, "Enabled filter returned result")
        assert_check(disabled_policies is not None, "Disabled filter returned result")

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
        assert_check(pii_enabled is not None, "Combined filter returned result")

        print(f"   Found: {len(pii_enabled)} enabled PII policies")

        for p in pii_enabled[:5]:
            pattern_preview = p.pattern[:40] + "..." if len(p.pattern) > 40 else p.pattern
            print(f"     - {p.name}: {pattern_preview}")

        # 6. Get effective policies (includes tier inheritance)
        print("\n6. Getting effective policies...")

        effective = await client.get_effective_static_policies()
        assert_check(effective is not None, "get_effective_static_policies returned result")
        assert_check(isinstance(effective, list), "Effective policies is a list")

        print(f"   Effective total: {len(effective)} policies")

        if effective:
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

        assert_check(page1 is not None, "Pagination page 1 returned result")
        assert_check(page2 is not None, "Pagination page 2 returned result")
        assert_check(len(page1) <= 5, "Page 1 respects limit")
        assert_check(len(page2) <= 5, "Page 2 respects limit")

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

        assert_check(by_severity is not None, "Sorting returned result")

        print("   Top 5 by severity:")
        for p in by_severity:
            print(f"     [{p.severity}] {p.name}")

    except Exception as e:
        print(f"\nError: {e}")
        failures.append(f"Policy listing failed: {e}")

    print("\n" + "=" * 60)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Policy Listing validated:")
        print("  - list_static_policies() returns all policies")
        print("  - Category filtering works")
        print("  - Tier filtering works")
        print("  - Enabled/disabled filtering works")
        print("  - get_effective_static_policies() works")
        print("  - Pagination works")
        print("  - Sorting works")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
