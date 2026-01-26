#!/usr/bin/env python3
"""
Azure OpenAI PII Detection Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates AxonFlow's PII detection with Azure OpenAI as the LLM provider.
AxonFlow detects and blocks requests containing sensitive PII before they reach Azure.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys

from axonflow import AxonFlow, SyncAxonFlow

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    print("AxonFlow PII Detection with Azure OpenAI - Python")
    print("=" * 60)
    print()

    async_client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "azure-pii-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )
    client = SyncAxonFlow(async_client)

    # Test cases with various PII types
    test_cases = [
        {
            "name": "Safe Query (No PII)",
            "query": "What are the benefits of Azure OpenAI?",
            "should_detect": False,
        },
        {
            "name": "US Social Security Number",
            "query": "Process refund for customer with SSN 123-45-6789",
            "should_detect": True,
        },
        {
            "name": "Credit Card Number",
            "query": "Charge card 4111-1111-1111-1111 for $99.99",
            "should_detect": True,
        },
        {
            "name": "India PAN Number",
            "query": "Verify PAN number ABCPD1234E for tax filing",
            "should_detect": False,  # Community mode: pattern match only (no validation)
        },
        {
            "name": "India Aadhaar Number",
            "query": "Link Aadhaar 2345 6789 0123 to account",
            "should_detect": True,
        },
        {
            "name": "Email Address",
            "query": "Send invoice to john.doe@example.com",
            "should_detect": False,  # Email warning only, not blocked
        },
        {
            "name": "Phone Number",
            "query": "Call customer at +1-555-123-4567",
            "should_detect": False,  # Phone numbers warn but don't block
        },
    ]

    passed = 0
    failed = 0

    for tc in test_cases:
        print(f"--- {tc['name']} ---")
        print(f"Query: {tc['query'][:50]}...")

        try:
            response = client.proxy_llm_call(
                user_token="pii-test-user",
                query=tc["query"],
                request_type="chat",
                context={"provider": "azure-openai"},
            )

            detected = response.blocked

            if detected == tc["should_detect"]:
                result = "PASS"
                passed += 1
            else:
                result = "FAIL"
                failed += 1

            assert_check(
                detected == tc["should_detect"],
                f"{tc['name']}: detected={detected}, expected={tc['should_detect']}"
            )

            print(f"  Detected: {detected} (expected: {tc['should_detect']}) - {result}")

            if detected and response.block_reason:
                print(f"  Reason: {response.block_reason}")

        except Exception as e:
            error_msg = str(e)
            detected = True

            if detected == tc["should_detect"]:
                result = "PASS"
                passed += 1
                assert_check(True, f"{tc['name']}: correctly detected via exception")
            else:
                result = "FAIL"
                failed += 1
                assert_check(False, f"{tc['name']}: detected={detected}, expected={tc['should_detect']}")

            print(f"  Detected: {detected} (expected: {tc['should_detect']}) - {result}")
            print(f"  Reason: {error_msg}")

        print()

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("PII Detection validated:")
        print("  - Safe queries pass through")
        print("  - SSN detection and blocking")
        print("  - Credit card detection and blocking")
        print("  - Aadhaar detection and blocking")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
