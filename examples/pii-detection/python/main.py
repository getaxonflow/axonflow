"""
AxonFlow PII Detection - Python

Demonstrates AxonFlow's built-in PII (Personally Identifiable Information) detection:
- US Social Security Numbers (SSN)
- Credit Card numbers
- India PAN (Permanent Account Number)
- India Aadhaar numbers
- Email addresses
- Phone numbers
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from axonflow import AxonFlow

load_dotenv()


async def main():
    print("AxonFlow PII Detection - Python")
    print("=" * 40)
    print()

    # Connect to AxonFlow
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "pii-detection-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # PII test cases
        test_cases = [
            {
                "name": "Safe Query (No PII)",
                "query": "What is the capital of France?",
                "should_block": False,
                "pii_type": "",
            },
            {
                "name": "US Social Security Number",
                "query": "Process refund for customer with SSN 123-45-6789",
                "should_block": True,
                "pii_type": "ssn",
            },
            {
                "name": "Credit Card Number",
                "query": "Charge card 4111-1111-1111-1111 for $99.99",
                "should_block": True,
                "pii_type": "credit_card",
            },
            {
                "name": "India PAN",
                "query": "Verify PAN number ABCDE1234F for tax filing",
                "should_block": True,
                "pii_type": "pan",
            },
            {
                "name": "India Aadhaar",
                "query": "Link Aadhaar 2345 6789 0123 to account",
                "should_block": True,
                "pii_type": "aadhaar",
            },
            {
                "name": "Email Address",
                "query": "Send invoice to john.doe@example.com",
                "should_block": True,
                "pii_type": "email",
            },
            {
                "name": "Phone Number",
                "query": "Call customer at +1-555-123-4567",
                "should_block": False,  # sys_pii_phone policy warns but doesn't block
                "pii_type": "phone",
            },
        ]

        passed = 0
        failed = 0

        for test in test_cases:
            print(f"Test: {test['name']}")
            query_preview = test["query"][:60] + "..." if len(test["query"]) > 60 else test["query"]
            print(f"  Query: {query_preview}")

            try:
                result = await axonflow.get_policy_approved_context(
                    user_token="pii-detection-user",
                    query=test["query"],
                )

                was_blocked = not result.approved

                if was_blocked:
                    print(f"  Result: BLOCKED")
                    print(f"  Reason: {result.block_reason}")
                else:
                    print(f"  Result: APPROVED")
                    print(f"  Context ID: {result.context_id}")

                if result.policies:
                    print(f"  Policies: {', '.join(result.policies)}")

                # Verify expected behavior
                if was_blocked == test["should_block"]:
                    print(f"  Test: PASS")
                    passed += 1
                else:
                    expected = "blocked" if test["should_block"] else "approved"
                    print(f"  Test: FAIL (expected {expected})")
                    failed += 1

            except Exception as e:
                print(f"  Result: ERROR - {e}")
                failed += 1

            print()

        print("=" * 40)
        print(f"Results: {passed} passed, {failed} failed")
        print()

        if failed > 0:
            print("Some tests failed. Check your AxonFlow policy configuration.")
            sys.exit(1)

        print("All PII detection tests passed!")
        print()
        print("Next steps:")
        print("  - Custom Policies: ../policies/")
        print("  - Code Governance: ../code-governance/")


if __name__ == "__main__":
    asyncio.run(main())
