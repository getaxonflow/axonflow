#!/usr/bin/env python3
"""
AxonFlow HITL - Create Policy with require_approval Action

This example demonstrates how to create a policy that triggers
Human-in-the-Loop (HITL) approval using the `require_approval` action.

The `require_approval` action:
- Enterprise: Pauses execution and creates an approval request in the HITL queue
- Community: Auto-approves immediately (upgrade path to Enterprise)

Use cases:
- High-value transaction oversight (EU AI Act Article 14, SEBI AI/ML)
- Admin access detection
- Sensitive data access control
"""

import os
import asyncio
from axonflow import AxonFlow
from axonflow.policies import (
    CreateStaticPolicyRequest,
    ListStaticPoliciesOptions,
    PolicyCategory,
    PolicySeverity,
    PolicyAction,
    PolicyTier,
)


async def main():
    # Initialize the client (client_id is used as tenant ID for policy APIs)
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo-tenant")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=client_id,
        client_secret=client_secret,
    ) as client:
        print("AxonFlow HITL - require_approval Policy Example")
        print("=" * 60)

        try:
            # 1. Create a policy with require_approval action
            print("\n1. Creating HITL oversight policy...")

            policy = await client.create_static_policy(
                CreateStaticPolicyRequest(
                    name="High-Value Transaction Oversight",
                    description="Require human approval for high-value financial decisions",
                    category=PolicyCategory.SECURITY_ADMIN,
                    # Pattern matches amounts over 1 million (₹, $, €)
                    pattern=r"(amount|value|total|transaction).*[₹$€]\s*[1-9][0-9]{6,}",
                    severity=PolicySeverity.HIGH,
                    enabled=True,
                    action=PolicyAction.REQUIRE_APPROVAL,  # Triggers HITL queue
                )
            )

            print(f"   Created policy: {policy.id}")
            print(f"   Name: {policy.name}")
            print(f"   Action: {policy.action}")
            print(f"   Tier: {policy.tier}")

            # 2. Test the pattern with sample inputs
            print("\n2. Testing pattern with sample inputs...")

            test_result = await client.test_pattern(
                policy.pattern,
                [
                    "Transfer amount $5,000,000 to account",  # Should match (5M)
                    "Transaction value ₹10,00,00,000",  # Should match (10Cr)
                    "Total: €2500000",  # Should match (2.5M)
                    "Payment of $500 completed",  # Should NOT match
                    "Amount: $999999",  # Should NOT match (under 1M)
                ],
            )

            print("\n   Test results:")
            for match in test_result.matches:
                icon = "✓ HITL" if match.matched else "✗ PASS"
                input_preview = match.input[:40] + "..." if len(match.input) > 40 else match.input
                print(f"   {icon}: \"{input_preview}\"")

            # 3. Create additional HITL policies
            print("\n3. Creating admin access oversight policy...")

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

            print(f"   Created: {admin_policy.name}")
            print(f"   Action: {admin_policy.action}")

            # 4. List all policies with require_approval action
            # Filter by tenant tier to get our custom policies (system policies are on first page)
            print("\n4. Listing all HITL policies...")

            all_policies = await client.list_static_policies(
                ListStaticPoliciesOptions(tier=PolicyTier.TENANT)
            )
            hitl_policies = [p for p in all_policies
                           if p.action == PolicyAction.REQUIRE_APPROVAL.value]

            print(f"   Found {len(hitl_policies)} HITL policies:")
            for p in hitl_policies:
                print(f"   - {p.name} ({p.severity})")

            # 5. Clean up test policies
            print("\n5. Cleaning up test policies...")
            await client.delete_static_policy(policy.id)
            await client.delete_static_policy(admin_policy.id)
            print("   Deleted test policies")

            print("\n" + "=" * 60)
            print("Example completed successfully!")
            print("\nNote: In Community Edition, require_approval auto-approves.")
            print("Upgrade to Enterprise for full HITL queue functionality.")

        except Exception as e:
            print(f"\nError: {e}")

            if "Connection refused" in str(e):
                print("\nHint: Make sure AxonFlow is running:")
                print("  docker compose up -d")

            raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
