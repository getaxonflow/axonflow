#!/usr/bin/env python3
"""
AxonFlow Static Policy Management - Python SDK

This example demonstrates and VALIDATES ALL static policy SDK methods:
- ListStaticPolicies
- GetStaticPolicy
- CreateStaticPolicy
- UpdateStaticPolicy
- DeleteStaticPolicy
- ToggleStaticPolicy
- TestPattern
- GetStaticPolicyVersions
- GetEffectiveStaticPolicies

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys
import time

from axonflow import AxonFlow, SyncAxonFlow
from axonflow.policies import (
    CreateStaticPolicyRequest,
    EffectivePoliciesOptions,
    ListStaticPoliciesOptions,
    PolicyAction,
    PolicyCategory,
    PolicySeverity,
    PolicyTier,
    UpdateStaticPolicyRequest,
)

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow Static Policy Management - Python SDK")
    print("=" * 55)
    print()

    async_client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )
    client = SyncAxonFlow(async_client)

    policy_id = None
    policy_name = f"demo-custom-policy-{int(time.time())}"

    try:
        # 1. LIST STATIC POLICIES
        print("1. ListStaticPolicies - Listing all static policies...")
        try:
            policies = client.list_static_policies(ListStaticPoliciesOptions(limit=10))
            assert_check(len(policies) > 0, "Found at least one policy")
            print(f"   Found {len(policies)} policies")
        except Exception as e:
            failures.append(f"list_static_policies failed: {e}")
        print()

        # 2. LIST BY CATEGORY
        print("2. ListStaticPolicies - Filtering by category...")
        try:
            sqli_policies = client.list_static_policies(
                ListStaticPoliciesOptions(category=PolicyCategory.SECURITY_SQLI, limit=5)
            )
            assert_check(isinstance(sqli_policies, list), "Category filter returns list")
            print(f"   Found {len(sqli_policies)} SQL injection policies")
        except Exception as e:
            failures.append(f"list_static_policies by category failed: {e}")
        print()

        # 3. CREATE STATIC POLICY
        print("3. CreateStaticPolicy - Creating a custom policy...")
        try:
            created = client.create_static_policy(
                CreateStaticPolicyRequest(
                    name=policy_name,
                    description="Demo policy for SDK testing",
                    category=PolicyCategory.CODE_SECRETS,
                    tier=PolicyTier.TENANT,
                    pattern=r"(?i)test_secret_\d+",
                    severity=PolicySeverity.MEDIUM,
                    enabled=True,
                    action=PolicyAction.WARN,
                )
            )
            policy_id = created.id
            assert_check(created.id != "", "Created policy has ID")
            assert_check(created.name == policy_name, "Created policy name matches")
            assert_check(created.enabled is True, "Created policy is enabled")
            print(f"   Created: {created.name} (ID: {created.id})")
        except Exception as e:
            failures.append(f"create_static_policy failed: {e}")
            return 1
        print()

        # 4. GET STATIC POLICY
        print("4. GetStaticPolicy - Retrieving policy by ID...")
        try:
            retrieved = client.get_static_policy(policy_id)
            assert_check(retrieved.id == policy_id, "Retrieved policy ID matches")
            assert_check(retrieved.name == policy_name, "Retrieved policy name matches")
            assert_check("test_secret" in retrieved.pattern, "Retrieved policy pattern matches")
        except Exception as e:
            failures.append(f"get_static_policy failed: {e}")
        print()

        # 5. TEST PATTERN
        print("5. TestPattern - Testing regex pattern...")
        try:
            test_inputs = [
                "test_secret_123",       # Should match
                "test_secret_abc",       # Should NOT match
                "TEST_SECRET_999",       # Should match (case insensitive)
                "normal text",           # Should NOT match
                "my test_secret_42 data",  # Should match
            ]
            result = client.test_pattern(pattern=r"(?i)test_secret_\d+", test_inputs=test_inputs)
            assert_check(result.valid is True, "Pattern is valid")
            match_count = sum(1 for m in result.matches if m.matched)
            assert_check(match_count == 3, f"Expected 3 matches, got {match_count}")
            print(f"   Pattern valid: {result.valid}, Matches: {match_count}/5")
        except Exception as e:
            failures.append(f"test_pattern failed: {e}")
        print()

        # 6. UPDATE STATIC POLICY
        print("6. UpdateStaticPolicy - Updating policy...")
        try:
            updated = client.update_static_policy(
                policy_id,
                UpdateStaticPolicyRequest(
                    description="Updated description",
                    severity=PolicySeverity.HIGH,
                    action=PolicyAction.BLOCK,
                ),
            )
            assert_check(updated.severity == PolicySeverity.HIGH, "Severity was updated")
            assert_check(updated.action == PolicyAction.BLOCK, "Action was updated")
        except Exception as e:
            failures.append(f"update_static_policy failed: {e}")
        print()

        # 7. GET POLICY VERSIONS
        print("7. GetStaticPolicyVersions - Getting version history...")
        try:
            versions = client.get_static_policy_versions(policy_id)
            # Version history may require Enterprise
            print(f"   Found {len(versions)} versions")
        except Exception as e:
            print(f"   Note: Version history may require Enterprise: {e}")
        print()

        # 8. TOGGLE STATIC POLICY
        print("8. ToggleStaticPolicy - Disabling then re-enabling...")
        try:
            toggled = client.toggle_static_policy(policy_id, enabled=False)
            assert_check(toggled.enabled is False, "Policy was disabled")
            toggled = client.toggle_static_policy(policy_id, enabled=True)
            assert_check(toggled.enabled is True, "Policy was re-enabled")
        except Exception as e:
            failures.append(f"toggle_static_policy failed: {e}")
        print()

        # 9. GET EFFECTIVE POLICIES
        print("9. GetEffectiveStaticPolicies - Getting effective policies...")
        try:
            effective = client.get_effective_static_policies(
                EffectivePoliciesOptions(include_disabled=False)
            )
            assert_check(isinstance(effective, list), "get_effective returns list")
            our_policy = next((p for p in effective if p.id == policy_id), None)
            assert_check(our_policy is not None, "Our policy is in effective list")
            print(f"   Found {len(effective)} effective policies")
        except Exception as e:
            failures.append(f"get_effective_static_policies failed: {e}")
        print()

        # 10. DELETE STATIC POLICY
        print("10. DeleteStaticPolicy - Cleaning up...")
        try:
            client.delete_static_policy(policy_id)
            # Verify deletion
            try:
                client.get_static_policy(policy_id)
                assert_check(False, "Policy should not exist after deletion")
            except Exception:
                assert_check(True, "Policy deleted successfully")
            policy_id = None
        except Exception as e:
            failures.append(f"delete_static_policy failed: {e}")
        print()

    finally:
        if policy_id:
            try:
                client.delete_static_policy(policy_id)
            except Exception:
                pass
        client.close()

    print("=" * 55)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Static Policy CRUD operations validated:")
        print("  - list_static_policies()")
        print("  - create_static_policy()")
        print("  - get_static_policy()")
        print("  - update_static_policy()")
        print("  - delete_static_policy()")
        print("  - toggle_static_policy()")
        print("  - test_pattern()")
        print("  - get_effective_static_policies()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
