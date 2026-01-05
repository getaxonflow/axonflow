"""
AxonFlow PII Detection - Python

Demonstrates AxonFlow's built-in PII (Personally Identifiable Information) detection:
- US Social Security Numbers (SSN)
- Credit Card numbers
- India PAN (Permanent Account Number)
- India Aadhaar numbers
- Email addresses
- Phone numbers

Default Behavior (Issue #891):
  PII detection defaults to "redact" mode - requests are APPROVED but flagged
  with requires_redaction=true for downstream redaction by the Orchestrator.
  Set PII_ACTION=block to restore blocking behavior.
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
    print("Default Mode: redact (PII flagged for redaction, not blocked)")
    print()

    # Connect to AxonFlow
    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "pii-detection-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # PII test cases
        # expect_redact: True = critical PII (requires_redaction=true)
        # expect_redact: False = non-critical or no PII (logged but not flagged)
        test_cases = [
            {
                "name": "Safe Query (No PII)",
                "query": "What is the capital of France?",
                "expect_redact": False,
            },
            {
                "name": "US Social Security Number (Critical PII)",
                "query": "Process refund for customer with SSN 123-45-6789",
                "expect_redact": True,
            },
            {
                "name": "Credit Card Number (Critical PII)",
                "query": "Charge card 4111-1111-1111-1111 for $99.99",
                "expect_redact": True,
            },
            {
                "name": "India PAN (Critical PII)",
                "query": "Verify PAN number ABCDE1234F for tax filing",
                "expect_redact": True,
            },
            {
                "name": "India Aadhaar (Critical PII)",
                "query": "Link Aadhaar 2345 6789 0123 to account",
                "expect_redact": True,
            },
            {
                "name": "Email Address (Non-Critical PII)",
                "query": "Send invoice to john.doe@gmail.com",
                "expect_redact": False,  # Medium severity - logged but not flagged
            },
            {
                "name": "Phone Number (Non-Critical PII)",
                "query": "Call customer at +1-555-123-4567",
                "expect_redact": False,  # Medium severity - logged but not flagged
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

                # Check if request was approved
                if result.approved:
                    # Check for redaction flag
                    requires_redaction = getattr(result, 'requires_redaction', False)
                    if requires_redaction:
                        print("  Result: APPROVED (requires redaction)")
                    else:
                        print("  Result: APPROVED")
                    print(f"  Context ID: {result.context_id}")
                else:
                    # Request was blocked (only if PII_ACTION=block)
                    print("  Result: BLOCKED")
                    print(f"  Reason: {result.block_reason}")

                if result.policies:
                    print(f"  Policies: {', '.join(result.policies)}")

                # Get actual redaction status
                actual_requires_redaction = getattr(result, 'requires_redaction', False) or not result.approved

                # Verify expected behavior
                if test["expect_redact"] and actual_requires_redaction:
                    print("  Test: PASS (PII detected, flagged for redaction)")
                    passed += 1
                elif not test["expect_redact"] and not actual_requires_redaction and result.approved:
                    print("  Test: PASS (no critical PII detected)")
                    passed += 1
                else:
                    expected = "requires_redaction=true" if test["expect_redact"] else "no critical PII"
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
        print("Configuration:")
        print("  - Default: PII_ACTION=redact (PII flagged for redaction, not blocked)")
        print("  - To block PII: PII_ACTION=block docker compose up -d")
        print()
        print("Next steps:")
        print("  - Custom Policies: ../policies/")
        print("  - Code Governance: ../code-governance/")


if __name__ == "__main__":
    asyncio.run(main())
