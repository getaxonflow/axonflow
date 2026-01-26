#!/usr/bin/env python3
"""
Compliance Policy Examples - Python

Demonstrates and VALIDATES using allowed_providers in dynamic policies for:
  - GDPR: EU data sovereignty
  - HIPAA: Healthcare data protection
  - RBI: India financial data sovereignty

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys

from axonflow import (
    AxonFlow,
    SyncAxonFlow,
    CreateDynamicPolicyRequest,
    DynamicPolicyAction,
    DynamicPolicyCondition,
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
    print("Compliance Dynamic Policies - Python SDK")
    print("=" * 50)
    print()

    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    async_client = AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        client_secret=client_secret,
    )
    client = SyncAxonFlow(async_client)

    created_policies: list[str] = []

    try:
        # Test 1: GDPR - EU Data Sovereignty
        print("1. CreateDynamicPolicy - GDPR EU Data Sovereignty")
        try:
            gdpr_request = CreateDynamicPolicyRequest(
                name="gdpr-eu-data-sovereignty",
                description="Route EU users to EU-hosted LLMs only (GDPR Article 44)",
                type="content",
                category="dynamic-compliance",
                conditions=[
                    DynamicPolicyCondition(field="user_region", operator="equals", value="EU")
                ],
                actions=[
                    DynamicPolicyAction(
                        type="route",
                        config={"allowed_providers": ["ollama", "azure-eu"]}
                    )
                ],
                enabled=True,
            )
            gdpr_policy = client.create_dynamic_policy(gdpr_request)
            assert_check(gdpr_policy.id != "", "GDPR policy has ID")
            assert_check(gdpr_policy.name == "gdpr-eu-data-sovereignty", "GDPR policy name matches")

            # Validate allowed_providers in action config
            if gdpr_policy.actions:
                for action in gdpr_policy.actions:
                    if action.config and "allowed_providers" in action.config:
                        providers = action.config["allowed_providers"]
                        assert_check(
                            "ollama" in providers,
                            f"GDPR policy has ollama in allowed_providers"
                        )
                        print(f"   Allowed providers: {providers}")

            created_policies.append(gdpr_policy.id)
            print(f"   Created: {gdpr_policy.id}")
        except Exception as e:
            failures.append(f"GDPR policy creation failed: {e}")
        print()

        # Test 2: HIPAA - Healthcare Data Protection
        print("2. CreateDynamicPolicy - HIPAA PHI Protection")
        try:
            hipaa_request = CreateDynamicPolicyRequest(
                name="hipaa-phi-protection",
                description="Route PHI queries to local LLM only (HIPAA Safe Harbor)",
                type="content",
                category="dynamic-compliance",
                conditions=[
                    DynamicPolicyCondition(field="request_type", operator="equals", value="healthcare"),
                    DynamicPolicyCondition(field="contains_phi", operator="equals", value=True),
                ],
                actions=[
                    DynamicPolicyAction(
                        type="route",
                        config={"allowed_providers": ["ollama"]}
                    )
                ],
                enabled=True,
            )
            hipaa_policy = client.create_dynamic_policy(hipaa_request)
            assert_check(hipaa_policy.id != "", "HIPAA policy has ID")
            assert_check(len(hipaa_policy.conditions or []) == 2, "HIPAA policy has 2 conditions")

            created_policies.append(hipaa_policy.id)
            print(f"   Created: {hipaa_policy.id}")
        except Exception as e:
            failures.append(f"HIPAA policy creation failed: {e}")
        print()

        # Test 3: RBI - India Financial Data Sovereignty
        print("3. CreateDynamicPolicy - RBI Financial Data Sovereignty")
        try:
            rbi_request = CreateDynamicPolicyRequest(
                name="rbi-financial-data-sovereignty",
                description="Route banking queries to India-hosted providers (RBI Data Localization)",
                type="content",
                category="dynamic-compliance",
                conditions=[
                    DynamicPolicyCondition(field="request_type", operator="equals", value="banking"),
                    DynamicPolicyCondition(field="user_region", operator="equals", value="IN"),
                ],
                actions=[
                    DynamicPolicyAction(
                        type="route",
                        config={"allowed_providers": ["azure-india", "ollama"]}
                    )
                ],
                enabled=True,
            )
            rbi_policy = client.create_dynamic_policy(rbi_request)
            assert_check(rbi_policy.id != "", "RBI policy has ID")

            created_policies.append(rbi_policy.id)
            print(f"   Created: {rbi_policy.id}")
        except Exception as e:
            failures.append(f"RBI policy creation failed: {e}")
        print()

        # Test 4: List all compliance policies
        print("4. ListDynamicPolicies - Find compliance policies")
        try:
            policies = client.list_dynamic_policies()
            assert_check(isinstance(policies, list), "list_dynamic_policies returns list")

            compliance_count = 0
            for p in policies:
                if p.actions:
                    for action in p.actions:
                        if action.config and "allowed_providers" in action.config:
                            compliance_count += 1
                            break

            assert_check(
                compliance_count >= 3,
                f"Found {compliance_count} policies with provider restrictions"
            )
            print(f"   Found {compliance_count} compliance policies with provider routing")
        except Exception as e:
            failures.append(f"list_dynamic_policies failed: {e}")
        print()

    finally:
        # Cleanup
        print("5. Cleanup - Deleting test policies")
        deleted = 0
        for policy_id in created_policies:
            try:
                client.delete_dynamic_policy(policy_id)
                deleted += 1
            except Exception as e:
                print(f"   Warning: Failed to delete {policy_id}: {e}")
        assert_check(deleted == len(created_policies), f"Deleted {deleted}/{len(created_policies)} policies")
        print()

        client.close()

    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Compliance Dynamic Policies validated:")
        print("  - create_dynamic_policy() with allowed_providers")
        print("  - GDPR, HIPAA, RBI data sovereignty patterns")
        print("  - list_dynamic_policies() filtering")
        print("  - delete_dynamic_policy()")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
