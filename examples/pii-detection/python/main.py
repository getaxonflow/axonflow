#!/usr/bin/env python3
"""
AxonFlow PII Detection - Python SDK

This example demonstrates and VALIDATES AxonFlow's PII detection:
- US Social Security Numbers (SSN)
- Credit Card numbers
- India PAN (Permanent Account Number)
- India Aadhaar numbers
- Email addresses
- Phone numbers

VALIDATION: This example exits with code 1 if any assertion fails.
This ensures CI/CD pipelines catch regressions.

Default Behavior (v11):
  The stored action of each matched PII policy decides. On the request side
  (this pre-check) the shipped SSN, credit card, PAN and Aadhaar policies store
  action_request=warn: the request is APPROVED and the matched policy ids are
  returned with it. Their stored response action is redact, so redaction
  happens on the response side. Environment variables no longer set detection
  actions. To change an outcome, record an organization override (Enterprise
  customer portal: PUT /api/v1/detection-posture/pii {"action":"block"}) or
  change the policy's action.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def get_env(key: str, default: str) -> str:
    return os.getenv(key, default)


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if not condition:
        failures.append(message)
        print(f"   ❌ FAIL: {message}")
    else:
        print(f"   ✓ PASS: {message}")


async def main() -> int:
    print("AxonFlow PII Detection - Python SDK")
    print("=" * 40)
    print()
    print("Stored policy actions decide: request-side PII warns (approved, policy recorded)")
    print()

    async with AxonFlow(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=get_env("AXONFLOW_DEBUG", "") == "true",
    ) as client:
        # PII test cases
        # expect_detect: True = critical PII (a policy matches; stored request action is warn)
        # expect_detect: False = non-critical or no PII (approved, no redaction flag)
        test_cases = [
            {
                "name": "Safe Query (No PII)",
                "query": "What is the capital of France?",
                "expect_detect": False,
            },
            {
                "name": "US Social Security Number (Critical PII)",
                "query": "Process refund for customer with SSN 123-45-6789",
                "expect_detect": True,
            },
            {
                "name": "Credit Card Number (Critical PII)",
                "query": "Charge card 4111-1111-1111-1111 for $99.99",
                "expect_detect": True,
            },
            {
                "name": "India PAN (Critical PII)",
                "query": "Verify PAN number ABCPD1234E for tax filing",
                "expect_detect": True,
            },
            {
                "name": "India Aadhaar (Critical PII)",
                "query": "Link Aadhaar 2345 6789 0123 to account",
                "expect_detect": True,
            },
            {
                "name": "Email Address (Non-Critical PII)",
                "query": "Send invoice to john.doe@gmail.com",
                "expect_detect": False,  # Medium severity - logged but not flagged
            },
            {
                "name": "Phone Number (Non-Critical PII)",
                "query": "Call customer at +1-555-123-4567",
                "expect_detect": False,  # Medium severity - logged but not flagged
            },
        ]

        for i, test in enumerate(test_cases, 1):
            print(f"Test {i}: {test['name']}")
            query_preview = (
                test["query"][:60] + "..."
                if len(test["query"]) > 60
                else test["query"]
            )
            print(f"  Query: {query_preview}")

            try:
                result = await client.get_policy_approved_context(
                    user_token=get_env("AXONFLOW_USER_TOKEN", "pii-detection-user"),
                    query=test["query"],
                )
            except Exception as e:
                print(f"   ❌ FATAL: get_policy_approved_context failed: {e}")
                return 1

            # Validate context ID (UUID format)
            assert_check(result.context_id != "", "context_id is not empty")

            # Check if request was approved
            requires_redaction = getattr(result, "requires_redaction", False)
            if result.approved:
                if requires_redaction:
                    print("   Status: APPROVED (requires redaction)")
                else:
                    print("   Status: APPROVED")
            else:
                # Blocked only when an organization override or a policy edit sets block
                print("   Status: BLOCKED")
                print(f"   Reason: {result.block_reason}")
            policies = getattr(result, "policies", None) or []
            if policies:
                print(f"   Policies: {policies}")

            # Verify expected behavior against the shipped stored actions
            if test["expect_detect"]:
                assert_check(
                    result.approved,
                    "Request approved (stored request action is warn, not block)",
                )
                assert_check(len(policies) > 0, "Critical PII detected (policy matched)")
            else:
                assert_check(
                    not requires_redaction and result.approved,
                    "No critical PII detected, request approved",
                )

            print()

        print("=" * 40)
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("PII types validated:")
            print("  - Safe query (no PII)")
            print("  - US SSN (critical)")
            print("  - Credit card (critical)")
            print("  - India PAN (critical)")
            print("  - India Aadhaar (critical)")
            print("  - Email (non-critical)")
            print("  - Phone (non-critical)")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
