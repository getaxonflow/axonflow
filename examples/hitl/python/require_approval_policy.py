#!/usr/bin/env python3
"""
AxonFlow HITL - Create Policy with require_approval Action

Demonstrates and VALIDATES how to create a policy that triggers
Human-in-the-Loop (HITL) approval using the `require_approval` action.

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python require_approval_policy.py
Prerequisites: docker compose up -d
"""

import os
import sys
import asyncio

from axonflow import AxonFlow
from axonflow.policies import (
    CreateStaticPolicyRequest,
    ListStaticPoliciesOptions,
    PolicyCategory,
    PolicySeverity,
    PolicyAction,
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
    print("AxonFlow HITL - require_approval Policy Example")
    print("=" * 55)
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo-tenant")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret")

    policy_id = None
    admin_policy_id = None

    async with AxonFlow(
        endpoint=agent_url,
        client_id=client_id,
        client_secret=client_secret,
    ) as client:

        try:
            # Test 1: Create a policy with require_approval action
            print("1. CreateStaticPolicy - HITL High-Value Transaction Oversight")
            try:
                policy = await client.create_static_policy(
                    CreateStaticPolicyRequest(
                        name="High-Value Transaction Oversight",
                        description="Require human approval for high-value financial decisions",
                        category=PolicyCategory.SECURITY_ADMIN,
                        pattern=r"(?i)(amount|value|total|transaction).*[₹$€]\s*[1-9][0-9]{6,}",
                        severity=PolicySeverity.HIGH,
                        enabled=True,
                        action=PolicyAction.REQUIRE_APPROVAL,
                    )
                )
                policy_id = policy.id
                assert_check(policy.id != "", "Policy has ID")
                assert_check(policy.name == "High-Value Transaction Oversight", "Policy name matches")
                assert_check(policy.action == PolicyAction.REQUIRE_APPROVAL.value, "Action is require_approval")
                print(f"   Created policy: {policy.id}")
            except Exception as e:
                failures.append(f"create_static_policy failed: {e}")
                return 1
            print()

            # Test 2: Test the pattern
            print("2. TestPattern - Validating HITL trigger patterns")
            try:
                test_result = await client.test_pattern(
                    policy.pattern,
                    [
                        "Transfer amount $5000000 to account",  # Should match (5M)
                        "Transaction value ₹10000000",  # Should match (10Cr)
                        "Total: €2500000",  # Should match (2.5M)
                        "Payment of $500 completed",  # Should NOT match
                        "Amount: $999999",  # Should NOT match (under 1M)
                    ],
                )
                assert_check(test_result.valid is True, "Pattern is valid regex")
                match_count = sum(1 for m in test_result.matches if m.matched)
                assert_check(match_count == 3, f"Expected 3 matches for high-value amounts (got {match_count})")
                print(f"   Pattern matches: {match_count}/5 (3 high-value, 2 below threshold)")
            except Exception as e:
                failures.append(f"test_pattern failed: {e}")
            print()

            # Test 3: Create admin access oversight policy
            print("3. CreateStaticPolicy - Admin Access Detection")
            try:
                admin_policy = await client.create_static_policy(
                    CreateStaticPolicyRequest(
                        name="Admin Access Detection",
                        description="Route admin operations through human review",
                        category=PolicyCategory.SECURITY_ADMIN,
                        pattern=r"(admin|root|superuser|sudo|DELETE\s+FROM|DROP\s+TABLE)",
                        severity=PolicySeverity.CRITICAL,
                        enabled=True,
                        action=PolicyAction.REQUIRE_APPROVAL,
                    )
                )
                admin_policy_id = admin_policy.id
                assert_check(admin_policy.id != "", "Admin policy has ID")
                assert_check(admin_policy.severity == PolicySeverity.CRITICAL.value, "Severity is CRITICAL")
            except Exception as e:
                failures.append(f"create admin policy failed: {e}")
            print()

            # Test 4: List policies with require_approval action
            print("4. ListStaticPolicies - Finding HITL policies")
            try:
                # Use higher limit to ensure we get the newly created policies
                all_policies = await client.list_static_policies(
                    ListStaticPoliciesOptions(limit=100)
                )
                assert_check(isinstance(all_policies, list), "list_static_policies returns list")

                hitl_policies = [p for p in all_policies
                               if p.action == PolicyAction.REQUIRE_APPROVAL.value]
                assert_check(len(hitl_policies) >= 2, f"Found at least 2 HITL policies (got {len(hitl_policies)})")
                print(f"   Found {len(hitl_policies)} HITL policies")
            except Exception as e:
                failures.append(f"list_static_policies failed: {e}")
            print()

        finally:
            # Cleanup
            print("5. Cleanup - Deleting test policies")
            if policy_id:
                try:
                    await client.delete_static_policy(policy_id)
                    assert_check(True, "Deleted high-value oversight policy")
                except Exception as e:
                    print(f"   Warning: Failed to delete policy: {e}")
            if admin_policy_id:
                try:
                    await client.delete_static_policy(admin_policy_id)
                    assert_check(True, "Deleted admin access policy")
                except Exception as e:
                    print(f"   Warning: Failed to delete admin policy: {e}")
            print()

    print("=" * 55)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("HITL Policy operations validated:")
        print("  - create_static_policy() with require_approval action")
        print("  - test_pattern() for HITL trigger validation")
        print("  - list_static_policies() filtering by action")
        print("  - delete_static_policy()")
        print()
        print("Note: In Community Edition, require_approval auto-approves.")
        print("Upgrade to Enterprise for full HITL queue functionality.")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
