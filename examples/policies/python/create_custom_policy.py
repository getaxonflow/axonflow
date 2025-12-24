"""
AxonFlow Policy Management - Create Custom Policy

This example demonstrates how to create a custom static policy
using the AxonFlow Python SDK.

Static policies are pattern-based rules that detect:
- PII (personally identifiable information)
- SQL injection attempts
- Sensitive data patterns
"""

import asyncio
import os

from axonflow import (
    AxonFlow,
    CreateStaticPolicyRequest,
    PolicyCategory,
    PolicySeverity,
)


async def main() -> None:
    """Create and test a custom policy."""
    # Initialize the client
    # For self-hosted Community, credentials not validated when running locally
    client = AxonFlow(
        agent_url=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",  # Used as tenant ID
        client_secret="test-secret",  # Not validated in Community mode
    )

    print("AxonFlow Policy Management - Create Custom Policy")
    print("=" * 60)

    try:
        # Create a custom PII detection policy
        # This policy detects email addresses from a specific domain
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

        print(f"   Created policy: {policy.id}")
        print(f"   Name: {policy.name}")
        print(f"   Tier: {policy.tier}")  # Will be 'tenant' for custom policies
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

        print(f"   Pattern valid: {test_result.valid}")
        print("\n   Test results:")

        for match in test_result.matches:
            icon = "\u2713" if match.matched else "\u2717"
            suffix = "-> MATCH" if match.matched else ""
            print(f'   {icon} "{match.input}" {suffix}')

        # Retrieve the created policy
        print("\n3. Retrieving created policy...")

        retrieved = await client.get_static_policy(policy.id)
        print(f"   Retrieved: {retrieved.name}")
        print(f"   Version: {retrieved.version or 1}")

        # Clean up - delete the test policy
        print("\n4. Cleaning up (deleting test policy)...")
        await client.delete_static_policy(policy.id)
        print("   Deleted successfully")

        print("\n" + "=" * 60)
        print("Example completed successfully!")

    except Exception as e:
        print(f"\nError: {e}")

        # Provide helpful error messages
        if "ECONNREFUSED" in str(e) or "Connection refused" in str(e):
            print("\nHint: Make sure AxonFlow is running:")
            print("  docker compose up -d")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
