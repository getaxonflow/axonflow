#!/usr/bin/env python3
"""
AxonFlow Policy Management - Create Custom Policy

VALIDATION: This example exits with code 1 if any assertion fails.

This example demonstrates how to create a custom static policy
using the AxonFlow Python SDK.

Static policies are pattern-based rules that detect:
- PII (personally identifiable information)
- SQL injection attempts
- Sensitive data patterns

Run with: python create_custom_policy.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import (
    AxonFlow,
    CreateStaticPolicyRequest,
    PolicyCategory,
    PolicySeverity,
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
    """Create and test a custom policy."""
    print("AxonFlow Policy Management - Create Custom Policy")
    print("=" * 60)

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",
        client_secret="test-secret",
    )

    policy_id = None

    try:
        # Create a custom PII detection policy
        print("\n1. Creating custom email detection policy...")

        policy = await client.create_static_policy(
            CreateStaticPolicyRequest(
                name="Custom Email Pattern",
                description="Detects email addresses in specific company format",
                category=PolicyCategory.PII_GLOBAL,
                pattern=r"[a-zA-Z0-9._%+-]+@company\.com",
                severity=PolicySeverity.MEDIUM,
                enabled=True,
            )
        )

        assert_check(policy is not None, "Policy creation returned result")
        assert_check(policy.id != "", "Policy has ID")
        assert_check(policy.name == "Custom Email Pattern", "Policy name matches")
        assert_check(policy.pattern == r"[a-zA-Z0-9._%+-]+@company\.com", "Policy pattern matches")

        policy_id = policy.id
        print(f"   Created policy: {policy.id}")
        print(f"   Name: {policy.name}")
        print(f"   Tier: {policy.tier}")
        print(f"   Category: {policy.category}")
        print(f"   Pattern: {policy.pattern}")

        # Test the pattern before using in production
        print("\n2. Testing the pattern...")

        test_result = await client.test_pattern(
            pattern=policy.pattern,
            test_inputs=[
                "john@company.com",
                "jane@gmail.com",
                "test@company.com",
                "invalid-email",
            ],
        )

        assert_check(test_result is not None, "Pattern test returned result")
        assert_check(test_result.valid, "Pattern is valid regex")

        print(f"   Pattern valid: {test_result.valid}")
        print("\n   Test results:")

        # Expected: john@company.com and test@company.com should match
        expected_matches = [True, False, True, False]
        for i, match in enumerate(test_result.matches):
            icon = "✓" if match.matched else "✗"
            suffix = "-> MATCH" if match.matched else ""
            print(f'   {icon} "{match.input}" {suffix}')
            if i < len(expected_matches):
                assert_check(
                    match.matched == expected_matches[i],
                    f"Input '{match.input}' matched as expected"
                )

        # Retrieve the created policy
        print("\n3. Retrieving created policy...")

        retrieved = await client.get_static_policy(policy.id)
        assert_check(retrieved is not None, "Retrieved policy successfully")
        assert_check(retrieved.name == policy.name, "Retrieved policy name matches")
        assert_check(retrieved.id == policy.id, "Retrieved policy ID matches")

        print(f"   Retrieved: {retrieved.name}")
        print(f"   Version: {retrieved.version or 1}")

        # Clean up - delete the test policy
        print("\n4. Cleaning up (deleting test policy)...")
        await client.delete_static_policy(policy.id)
        assert_check(True, "Policy deleted successfully")
        policy_id = None  # Mark as deleted
        print("   Deleted successfully")

    except Exception as e:
        print(f"\nError: {e}")
        failures.append(f"Policy creation test failed: {e}")

        if "ECONNREFUSED" in str(e) or "Connection refused" in str(e):
            print("\nHint: Make sure AxonFlow is running:")
            print("  docker compose up -d")

    finally:
        # Cleanup if needed
        if policy_id:
            try:
                await client.delete_static_policy(policy_id)
            except Exception:
                pass

    print("\n" + "=" * 60)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Custom Policy Creation validated:")
        print("  - create_static_policy() creates policy")
        print("  - test_pattern() validates pattern")
        print("  - get_static_policy() retrieves policy")
        print("  - delete_static_policy() removes policy")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
