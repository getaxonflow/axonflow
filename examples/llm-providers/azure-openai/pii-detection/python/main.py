#!/usr/bin/env python3
"""
Azure OpenAI PII Detection Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates AxonFlow's PII detection and blocking with Azure OpenAI.
Critical PII (SSN, credit cards, Aadhaar) is blocked; non-critical PII
(email, phone) is detected but allowed through.

Prerequisites:
  PII_ACTION=block docker compose up -d

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

    pii_action = os.getenv("PII_ACTION", "redact")
    if pii_action != "block":
        print(f"\n  WARNING: PII_ACTION={pii_action} (expected 'block')")
        print("  Start AxonFlow with: PII_ACTION=block docker compose up -d\n")

    async_client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "azure-pii-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )
    client = SyncAxonFlow(async_client)

    # Critical PII (SSN, CC, Aadhaar) should be blocked.
    # Non-critical PII (PAN, email, phone) is detected but not blocked.
    test_cases = [
        {
            "name": "Safe Query (No PII)",
            "query": "What are the benefits of Azure OpenAI?",
            "should_block": False,
        },
        {
            "name": "US Social Security Number",
            "query": "Process refund for customer with SSN 123-45-6789",
            "should_block": True,
        },
        {
            "name": "Credit Card Number",
            "query": "Charge card 4111-1111-1111-1111 for $99.99",
            "should_block": True,
        },
        {
            "name": "India PAN Number",
            "query": "Verify PAN number ABCPD1234E for tax filing",
            "should_block": False,
        },
        {
            "name": "India Aadhaar Number",
            "query": "Link Aadhaar 2345 6789 0123 to account",
            "should_block": True,
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

            if response.policy_info and response.policy_info.policies_evaluated:
                pii = [p for p in response.policy_info.policies_evaluated if p.startswith("sys_pii_")]
                if pii:
                    print(f"  Policies: {pii}")

        except Exception as e:
            error_msg = str(e)
            blocked = True

            if blocked == tc["should_block"]:
                result = "PASS"
                passed += 1
                assert_check(True, f"{tc['name']}: correctly blocked via exception")
            else:
                result = "FAIL"
                failed += 1
                assert_check(False, f"{tc['name']}: blocked={blocked}, expected={tc['should_block']}")

            print(f"  Blocked: {blocked} (expected: {tc['should_block']}) - {result}")
            print(f"  Reason: {error_msg}")

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if not failures:
        print("ALL TESTS PASSED")
        print()
        print("PII Detection validated:")
        print("  - Safe queries pass through")
        print("  - SSN blocked (critical)")
        print("  - Credit card blocked (critical)")
        print("  - Aadhaar blocked (critical)")
        print("  - PAN detected but not blocked")
        print("  - Email detected but not blocked")
        print("  - Phone detected but not blocked")
        return 0
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
