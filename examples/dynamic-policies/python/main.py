#!/usr/bin/env python3
"""
Dynamic Policy Management Example - Python

Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
Dynamic policies use an LLM to evaluate complex, context-aware rules that
can't be expressed with simple regex patterns.

SDK Methods demonstrated:
  - list_dynamic_policies()
  - create_dynamic_policy()
  - get_dynamic_policy()
  - update_dynamic_policy()
  - delete_dynamic_policy()
  - toggle_dynamic_policy()
  - get_effective_dynamic_policies()

Usage:
    python main.py

Environment:
    AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
    AXONFLOW_LICENSE_KEY - Required for dynamic policies
"""

import asyncio
import os
from axonflow import AxonFlow, CreateDynamicPolicyRequest, UpdateDynamicPolicyRequest, DynamicPolicyCondition, DynamicPolicyAction


async def main():
    # Initialize client
    endpoint = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo-tenant")  # Used as tenant ID
    license_key = os.getenv("AXONFLOW_LICENSE_KEY", "")

    client = AxonFlow(
        endpoint=endpoint,
        client_id=client_id,
        license_key=license_key if license_key else None,
    )

    print("=== Dynamic Policy Management Example ===\n")

    created_policy = None

    try:
        # 1. List existing dynamic policies
        print("1. Listing existing dynamic policies...")
        policies = await client.list_dynamic_policies()
        print(f"   Found {len(policies)} dynamic policies")
        for p in policies:
            print(f"   - {p.id}: {p.name} (enabled: {p.enabled})")

        # 2. Create a new dynamic policy
        print("\n2. Creating a new dynamic policy...")
        new_policy = CreateDynamicPolicyRequest(
            name="financial-advice-guard",
            description="Block requests that ask for specific financial advice",
            type="risk",  # Dynamic policy type: risk, content, user, cost
            conditions=[
                DynamicPolicyCondition(
                    field="query",
                    operator="contains",
                    value="investment",
                )
            ],
            actions=[
                DynamicPolicyAction(
                    type="block",
                    config={"message": "Financial advice requests are not allowed"},
                )
            ],
            enabled=True,
        )

        created_policy = await client.create_dynamic_policy(new_policy)
        print(f"   Created policy: {created_policy.name} (ID: {created_policy.id})")

        # 3. Get the policy by ID
        print("\n3. Getting policy by ID...")
        policy = await client.get_dynamic_policy(created_policy.id)
        print(f"   Policy: {policy.name}")
        print(f"   Description: {policy.description}")
        print(f"   Type: {policy.type}")
        print(f"   Conditions: {len(policy.conditions or [])} defined")
        print(f"   Actions: {len(policy.actions or [])} defined")

        # 4. Update the policy
        print("\n4. Updating policy description...")
        update = UpdateDynamicPolicyRequest(
            description="Block requests asking for specific financial or investment advice",
        )
        updated = await client.update_dynamic_policy(created_policy.id, update)
        print(f"   Updated description: {updated.description}")

        # 5. Toggle policy (disable it) - using update since PATCH not supported
        print("\n5. Toggling policy (disabling)...")
        toggle_update = UpdateDynamicPolicyRequest(enabled=False)
        toggled = await client.update_dynamic_policy(created_policy.id, toggle_update)
        print(f"   Policy enabled: {toggled.enabled}")

        # 6. Get effective dynamic policies
        print("\n6. Getting effective dynamic policies...")
        effective = await client.get_effective_dynamic_policies()
        print(f"   Found {len(effective)} effective dynamic policies")

    finally:
        # 7. Delete the test policy (cleanup)
        if created_policy:
            print("\n7. Cleaning up - deleting test policy...")
            try:
                await client.delete_dynamic_policy(created_policy.id)
                print("   Policy deleted successfully")
            except Exception as e:
                print(f"   Failed to delete policy: {e}")

    print("\n=== Dynamic Policy Example Complete ===")


if __name__ == "__main__":
    asyncio.run(main())
