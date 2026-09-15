#!/usr/bin/env python3
"""
Azure OpenAI PII Detection Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates AxonFlow's PII detection with Azure OpenAI.

v11: the stored policy action decides. With the shipped actions and no
organization override, PII is detected but NOT blocked: sys_pii_ssn and
sys_pii_credit_card store warn for the request phase (and redact for the
response phase), and the code-backed India PII detector only records unless an
org override says otherwise. This example validates that outcome and checks
the matched policy ids in policy_info.policies_evaluated.

To block PII, record an organization override of category "pii" with action
"block" (PUT /api/v1/detection-posture/pii on the customer portal API,
Enterprise) or change the policy's action. PII_ACTION no longer sets an action.

Prerequisites:
  docker compose up -d

Run with: python main.py
"""

import os
import sys

from axonflow import AxonFlow, SyncAxonFlow

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow PII Detection with Azure OpenAI - Python")
    print("=" * 60)

    async_client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "azure-pii-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )
    client = SyncAxonFlow(async_client)

    # With the shipped actions and no org override, nothing here is blocked.
    # expect_policy names the policy that must be reported as detected, where the
    # shipped row is known to match the query.
    test_cases = [
        {
            "name": "Safe Query (No PII)",
            "query": "What are the benefits of Azure OpenAI?",
            "should_block": False,
        },
        {
            "name": "US Social Security Number",
            "query": "Process refund for customer with SSN 123-45-6789",
            "should_block": False,
            "expect_policy": "sys_pii_ssn",
        },
        {
            "name": "Credit Card Number",
            "query": "Charge card 4111-1111-1111-1111 for $99.99",
            "should_block": False,
            "expect_policy": "sys_pii_credit_card",
        },
        {
            "name": "India PAN Number",
            "query": "Verify PAN number ABCPD1234E for tax filing",
            "should_block": False,
        },
        {
            "name": "India Aadhaar Number",
            "query": "Link Aadhaar 2345 6789 0123 to account",
            "should_block": False,
        },
        {
            "name": "Email Address",
            "query": "Send invoice to john.doe@example.com",
            "should_block": False,
        },
        {
            "name": "Phone Number",
            "query": "Call customer at +1-555-123-4567",
            "should_block": False,
        },
    ]

    passed = 0
    failed = 0

    for tc in test_cases:
        print(f"\n--- {tc['name']} ---")
        print(f"Query: {tc['query'][:50]}...")

        try:
            response = client.proxy_llm_call(
                user_token=os.getenv("AXONFLOW_USER_TOKEN", "pii-test-user"),
                query=tc["query"],
                request_type="chat",
                context={"provider": "azure-openai"},
            )

            blocked = response.blocked

            if blocked == tc["should_block"]:
                result = "PASS"
                passed += 1
            else:
                result = "FAIL"
                failed += 1

            assert_check(
                blocked == tc["should_block"],
                f"{tc['name']}: blocked={blocked}, expected={tc['should_block']}"
            )

            print(f"  Blocked: {blocked} (expected: {tc['should_block']}) - {result}")

            if response.blocked and response.block_reason:
                print(f"  Reason: {response.block_reason}")
                print("  (not the shipped outcome: an org pii=block override or an edited policy action is in force)")

            evaluated = []
            if response.policy_info and response.policy_info.policies_evaluated:
                evaluated = response.policy_info.policies_evaluated
                pii = [p for p in evaluated if p.startswith("sys_pii_")]
                if pii:
                    print(f"  Detected (warned): {pii}")

            if tc.get("expect_policy"):
                assert_check(
                    tc["expect_policy"] in evaluated,
                    f"{tc['name']}: {tc['expect_policy']} detected",
                )

        except Exception as e:
            # An exception is not a verdict: record it as a failure, never as a block.
            failed += 1
            assert_check(False, f"{tc['name']}: request failed: {e}")

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("PII Detection validated (shipped actions, no org override):")
        print("  - Safe queries pass through")
        print("  - SSN detected and warned, not blocked")
        print("  - Credit card detected and warned, not blocked")
        print("  - Aadhaar, PAN, email, phone not blocked")
        print()
        print("To block PII, record an org override pii=block or change the policy action.")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
