#!/usr/bin/env python3
"""
AxonFlow Static Policy Management - Python SDK (Comprehensive)

This example demonstrates ALL static policy SDK methods:
- ListStaticPolicies
- GetStaticPolicy
- CreateStaticPolicy
- UpdateStaticPolicy
- DeleteStaticPolicy
- ToggleStaticPolicy
- TestPattern
- GetStaticPolicyVersions
- GetEffectiveStaticPolicies

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
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


def get_env(key: str, default: str) -> str:
    """Get environment variable with default value."""
    return os.getenv(key, default)


def main():
    print("AxonFlow Static Policy Management - Python SDK")
    print("=" * 55)
    print()

    # Create AxonFlow client
    async_client = AxonFlow(
        agent_url=get_env("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        orchestrator_url=get_env("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    )
    client = SyncAxonFlow(async_client)

    # Unique ID for our test policy
    policy_id = None
    policy_name = f"demo-custom-policy-{int(time.time())}"

    try:
        # ========================================
        # 1. LIST STATIC POLICIES
        # ========================================
        print("1. list_static_policies - Listing all static policies...")
        try:
            policies = client.list_static_policies(
                ListStaticPoliciesOptions(limit=10)
            )
            print(f"   Found {len(policies)} policies")
            for p in policies[:3]:
                status = "enabled" if p.enabled else "disabled"
                print(f"   - {p.name}: {p.category} ({status})")
            if len(policies) > 3:
                print(f"   ... and {len(policies) - 3} more")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 2. LIST BY CATEGORY
        # ========================================
        print("2. list_static_policies - Filtering by category...")
        try:
            sqli_policies = client.list_static_policies(
                ListStaticPoliciesOptions(
                    category=PolicyCategory.SECURITY_SQLI,
                    limit=5,
                )
            )
            print(f"   Found {len(sqli_policies)} SQL injection policies")
            for p in sqli_policies[:3]:
                print(f"   - {p.name}: severity={p.severity}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 3. CREATE STATIC POLICY
        # ========================================
        print("3. create_static_policy - Creating a custom policy...")
        try:
            # Using CODE_SECRETS category - appropriate for custom tenant policies
            # that detect sensitive patterns in generated code.
            created = client.create_static_policy(
                CreateStaticPolicyRequest(
                    name=policy_name,
                    description="Demo policy for SDK testing - detects test secrets in code",
                    category=PolicyCategory.CODE_SECRETS,
                    tier=PolicyTier.TENANT,
                    pattern=r"(?i)(test_secret_\d+|demo_inject_\w+)",
                    severity=PolicySeverity.MEDIUM,
                    enabled=True,
                    action=PolicyAction.WARN,
                )
            )
            policy_id = created.id
            print(f"   Created: {created.name}")
            print(f"   ID: {created.id}")
            print(f"   Category: {created.category}")
            print(f"   Action: {created.action}")
        except Exception as e:
            print(f"   ERROR: {e}")
            return
        print()

        # ========================================
        # 4. GET STATIC POLICY
        # ========================================
        print("4. get_static_policy - Retrieving policy by ID...")
        try:
            retrieved = client.get_static_policy(policy_id)
            print(f"   Retrieved: {retrieved.name}")
            print(f"   Pattern: {retrieved.pattern}")
            print(f"   Enabled: {retrieved.enabled}")
            print(f"   Version: {retrieved.version or 1}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 5. TEST PATTERN
        # ========================================
        print("5. test_pattern - Testing regex pattern...")
        try:
            test_inputs = [
                "test_secret_123",      # Should match
                "test_secret_abc",      # Should NOT match (no digits)
                "TEST_SECRET_999",      # Should match (case insensitive)
                "normal text",          # Should NOT match
                "my test_secret_42 data",  # Should match
            ]
            result = client.test_pattern(
                pattern=r"(?i)test_secret_\d+",
                test_inputs=test_inputs,
            )
            print(f"   Pattern valid: {result.valid}")
            print("   Match results:")
            for match in result.matches:
                status = "MATCH" if match.matched else "NO MATCH"
                print(f"     [{status}] {match.input}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 6. UPDATE STATIC POLICY
        # ========================================
        print("6. update_static_policy - Updating policy...")
        try:
            updated = client.update_static_policy(
                policy_id,
                UpdateStaticPolicyRequest(
                    description="Updated description - now with stricter severity",
                    severity=PolicySeverity.HIGH,
                    action=PolicyAction.BLOCK,
                ),
            )
            print(f"   Updated: {updated.name}")
            print(f"   New severity: {updated.severity}")
            print(f"   New action: {updated.action}")
            print(f"   New version: {updated.version or 2}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 7. GET POLICY VERSIONS
        # ========================================
        print("7. get_static_policy_versions - Getting version history...")
        try:
            versions = client.get_static_policy_versions(policy_id)
            print(f"   Found {len(versions)} versions")
            for v in versions:
                print(f"   - v{v.version}: {v.change_type} at {v.changed_at}")
                if v.change_description:
                    print(f"     Description: {v.change_description}")
        except Exception as e:
            print(f"   Note: Version history may require Enterprise: {e}")
        print()

        # ========================================
        # 8. TOGGLE STATIC POLICY
        # ========================================
        print("8. toggle_static_policy - Disabling policy...")
        try:
            toggled = client.toggle_static_policy(policy_id, enabled=False)
            print(f"   Policy: {toggled.name}")
            print(f"   Enabled: {toggled.enabled}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        print("   Enabling policy again...")
        try:
            toggled = client.toggle_static_policy(policy_id, enabled=True)
            print(f"   Enabled: {toggled.enabled}")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 9. GET EFFECTIVE POLICIES
        # ========================================
        print("9. get_effective_static_policies - Getting effective policies...")
        try:
            effective = client.get_effective_static_policies(
                EffectivePoliciesOptions(include_disabled=False)
            )
            print(f"   Found {len(effective)} effective policies")
            # Check if our policy is in the effective list
            our_policy = next((p for p in effective if p.id == policy_id), None)
            if our_policy:
                print(f"   Our policy is effective: {our_policy.name}")
            else:
                print("   Our policy is not in the effective list (may be disabled)")
        except Exception as e:
            print(f"   ERROR: {e}")
        print()

        # ========================================
        # 10. DELETE STATIC POLICY
        # ========================================
        print("10. delete_static_policy - Cleaning up...")
        try:
            client.delete_static_policy(policy_id)
            print(f"   Deleted policy: {policy_name}")
            policy_id = None  # Mark as deleted
        except Exception as e:
            print(f"   WARNING: Failed to delete policy: {e}")
        print()

        print("=" * 55)
        print("All 10 Static Policy SDK methods tested!")
        print()
        print("Methods demonstrated:")
        print("  1. list_static_policies()           - List with filtering")
        print("  2. list_static_policies(category)   - Filter by category")
        print("  3. create_static_policy()           - Create new policy")
        print("  4. get_static_policy()              - Get by ID")
        print("  5. test_pattern()                   - Test regex pattern")
        print("  6. update_static_policy()           - Update policy")
        print("  7. get_static_policy_versions()     - Version history")
        print("  8. toggle_static_policy()           - Enable/disable")
        print("  9. get_effective_static_policies()  - Effective policies")
        print(" 10. delete_static_policy()           - Delete policy")

    finally:
        # Cleanup if policy wasn't deleted
        if policy_id:
            try:
                client.delete_static_policy(policy_id)
                print(f"\nCleanup: Deleted policy {policy_name}")
            except Exception:
                pass
        client.close()


if __name__ == "__main__":
    main()
