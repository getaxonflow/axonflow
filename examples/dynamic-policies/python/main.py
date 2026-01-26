#!/usr/bin/env python3
"""
Dynamic Policy Management Example - Python

Demonstrates and VALIDATES CRUD operations for dynamic policies.

SDK Methods demonstrated:
  - list_dynamic_policies()
  - create_dynamic_policy()
  - get_dynamic_policy()
  - update_dynamic_policy()
  - delete_dynamic_policy()
  - get_effective_dynamic_policies()

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys
import time

from axonflow import (
    AxonFlow,
    CreateDynamicPolicyRequest,
    UpdateDynamicPolicyRequest,
    DynamicPolicyCondition,
    DynamicPolicyAction,
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
    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "dynamic-policies-example")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    client = AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret if client_secret else None,
    )

    print("AxonFlow Dynamic Policy Management - Python SDK")
    print("=" * 50)
    print()

    policy_name = f"test-policy-{int(time.time())}"
    created_policy = None

    try:
        # 1. List existing dynamic policies
        print("1. ListDynamicPolicies - Listing existing policies...")
        policies = await client.list_dynamic_policies()
        assert_check(isinstance(policies, list), "list_dynamic_policies returns list")
        print(f"   Found {len(policies)} dynamic policies")
        print()

        # 2. Create a new dynamic policy
        print("2. CreateDynamicPolicy - Creating test policy...")
        new_policy = CreateDynamicPolicyRequest(
            name=policy_name,
            description="Test policy for SDK validation",
            type="risk",
            conditions=[
                DynamicPolicyCondition(
                    field="query",
                    operator="contains",
                    value="test-blocked-keyword",
                )
            ],
            actions=[
                DynamicPolicyAction(
                    type="block",
                    config={"message": "Test block message"},
                )
            ],
            enabled=True,
        )

        created_policy = await client.create_dynamic_policy(new_policy)
        assert_check(created_policy.id != "", "Created policy has ID")
        assert_check(created_policy.name == policy_name, "Created policy name matches")
        assert_check(created_policy.enabled is True, "Created policy is enabled")
        print(f"   Created: {created_policy.name} (ID: {created_policy.id})")
        print()

        # 3. Get the policy by ID
        print("3. GetDynamicPolicy - Retrieving policy by ID...")
        policy = await client.get_dynamic_policy(created_policy.id)
        assert_check(policy.id == created_policy.id, "Retrieved policy ID matches")
        assert_check(policy.name == policy_name, "Retrieved policy name matches")
        assert_check(len(policy.conditions or []) == 1, "Policy has 1 condition")
        assert_check(len(policy.actions or []) == 1, "Policy has 1 action")
        print()

        # 4. Update the policy
        print("4. UpdateDynamicPolicy - Updating description...")
        new_desc = "Updated description for SDK validation"
        update = UpdateDynamicPolicyRequest(description=new_desc)
        updated = await client.update_dynamic_policy(created_policy.id, update)
        assert_check(updated.description == new_desc, "Description was updated")
        print()

        # 5. Toggle policy (disable it)
        print("5. ToggleDynamicPolicy - Disabling policy...")
        toggle_update = UpdateDynamicPolicyRequest(enabled=False)
        toggled = await client.update_dynamic_policy(created_policy.id, toggle_update)
        assert_check(toggled.enabled is False, "Policy was disabled")
        print()

        # 6. Get effective dynamic policies (should not include disabled)
        print("6. GetEffectiveDynamicPolicies - Checking effective policies...")
        effective = await client.get_effective_dynamic_policies()
        our_policy_effective = any(p.id == created_policy.id for p in effective)
        assert_check(not our_policy_effective, "Disabled policy not in effective list")
        print(f"   Found {len(effective)} effective policies")
        print()

        # 7. Re-enable and verify
        print("7. ToggleDynamicPolicy - Re-enabling policy...")
        enable_update = UpdateDynamicPolicyRequest(enabled=True)
        reenabled = await client.update_dynamic_policy(created_policy.id, enable_update)
        assert_check(reenabled.enabled is True, "Policy was re-enabled")
        print()

    finally:
        # 8. Delete the test policy (cleanup)
        if created_policy:
            print("8. DeleteDynamicPolicy - Cleaning up...")
            try:
                await client.delete_dynamic_policy(created_policy.id)
                # Verify deletion
                try:
                    await client.get_dynamic_policy(created_policy.id)
                    assert_check(False, "Policy should not exist after deletion")
                except Exception:
                    assert_check(True, "Policy deleted successfully")
            except Exception as e:
                failures.append(f"Failed to delete policy: {e}")
            print()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Dynamic Policy CRUD operations validated:")
        print("  - list_dynamic_policies()")
        print("  - create_dynamic_policy()")
        print("  - get_dynamic_policy()")
        print("  - update_dynamic_policy()")
        print("  - delete_dynamic_policy()")
        print("  - get_effective_dynamic_policies()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
