"""
Compliance Policy Examples - Python

Demonstrates using allowed_providers in dynamic policies for:
  - GDPR: EU data sovereignty
  - HIPAA: Healthcare data protection
  - RBI: India financial data sovereignty

SDK Methods demonstrated:
  - create_dynamic_policy() with actions containing allowed_providers config
  - list_dynamic_policies()
  - delete_dynamic_policy()

Usage:
  python main.py

Environment:
  AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
  AXONFLOW_LICENSE_KEY - Required for dynamic policies
"""

import os
from axonflow import (
    AxonFlow,
    SyncAxonFlow,
    CreateDynamicPolicyRequest,
    DynamicPolicyAction,
    DynamicPolicyCondition,
)


def main():
    # Initialize client
    endpoint = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080")
    license_key = os.getenv("AXONFLOW_LICENSE_KEY", "")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo-tenant")

    async_client = AxonFlow(
        endpoint=endpoint,
        license_key=license_key,
        client_id=client_id,
    )
    client = SyncAxonFlow(async_client)

    print("=== Compliance Policy Examples ===\n")

    created_policies = []

    # 1. GDPR - EU Data Sovereignty
    print("1. Creating GDPR policy for EU data sovereignty...")
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
        print(f"   Created: {gdpr_policy.name} (ID: {gdpr_policy.id})")
        # Extract allowed_providers from action config
        if gdpr_policy.actions:
            for action in gdpr_policy.actions:
                if action.config and "allowed_providers" in action.config:
                    print(f"   Allowed providers: {action.config['allowed_providers']}")
        created_policies.append(gdpr_policy.id)
    except Exception as e:
        print(f"   Failed to create GDPR policy: {e}")

    # 2. HIPAA - Healthcare Data Protection
    print("\n2. Creating HIPAA policy for PHI protection...")
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
        print(f"   Created: {hipaa_policy.name} (ID: {hipaa_policy.id})")
        if hipaa_policy.actions:
            for action in hipaa_policy.actions:
                if action.config and "allowed_providers" in action.config:
                    print(f"   Allowed providers: {action.config['allowed_providers']}")
        created_policies.append(hipaa_policy.id)
    except Exception as e:
        print(f"   Failed to create HIPAA policy: {e}")

    # 3. RBI - India Financial Data Sovereignty
    print("\n3. Creating RBI policy for financial data sovereignty...")
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
        print(f"   Created: {rbi_policy.name} (ID: {rbi_policy.id})")
        if rbi_policy.actions:
            for action in rbi_policy.actions:
                if action.config and "allowed_providers" in action.config:
                    print(f"   Allowed providers: {action.config['allowed_providers']}")
        created_policies.append(rbi_policy.id)
    except Exception as e:
        print(f"   Failed to create RBI policy: {e}")

    # 4. List all compliance policies
    print("\n4. Listing all compliance policies...")
    try:
        policies = client.list_dynamic_policies()
        compliance_count = 0
        for p in policies:
            # Check for allowed_providers in action config
            if p.actions:
                for action in p.actions:
                    if action.config and "allowed_providers" in action.config:
                        compliance_count += 1
                        print(f"   - {p.name}: providers={action.config['allowed_providers']}")
                        break
        print(f"   Found {compliance_count} policies with provider restrictions")
    except Exception as e:
        print(f"   Failed to list policies: {e}")

    # 5. Cleanup
    print("\n5. Cleaning up test policies...")
    for policy_id in created_policies:
        try:
            client.delete_dynamic_policy(policy_id)
        except Exception as e:
            print(f"   Failed to delete {policy_id}: {e}")
    print(f"   Deleted {len(created_policies)} test policies")

    print("\n=== Compliance Policy Examples Complete ===")


if __name__ == "__main__":
    main()
