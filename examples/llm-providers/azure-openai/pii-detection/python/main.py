#!/usr/bin/env python3
"""Azure OpenAI PII Detection Example

Demonstrates AxonFlow's PII detection with Azure OpenAI as the LLM provider.
AxonFlow detects and blocks requests containing sensitive PII before they reach Azure.
"""

import os
from axonflow import AxonFlow, SyncAxonFlow

def main():
    print("AxonFlow PII Detection with Azure OpenAI - Python")
    print("=" * 60)
    print()

    # Initialize AxonFlow client (using SyncAxonFlow for synchronous operations)
    async_client = AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "azure-pii-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        license_key=os.getenv("AXONFLOW_LICENSE_KEY", ""),
    )
    client = SyncAxonFlow(async_client)

    # Test cases with various PII types
    # Note: "should_detect" means the PII is detected (may block or require redaction)
    test_cases = [
        {
            "name": "Safe Query (No PII)",
            "query": "What are the benefits of Azure OpenAI?",
            "should_detect": False,
        },
        {
            "name": "US Social Security Number",
            "query": "Process refund for customer with SSN 123-45-6789",
            "should_detect": True,  # SSN triggers redaction requirement
        },
        {
            "name": "Credit Card Number",
            "query": "Charge card 4111-1111-1111-1111 for $99.99",
            "should_detect": True,  # Credit cards trigger PCI redaction
        },
        {
            "name": "India PAN Number",
            "query": "Verify PAN number ABCDE1234F for tax filing",
            "should_detect": False,  # Community mode: pattern match only (no validation)
        },
        {
            "name": "India Aadhaar Number",
            "query": "Link Aadhaar 2345 6789 0123 to account",
            "should_detect": True,  # Blocked by system policy
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
            response = client.execute_query(
                user_token="pii-test-user",
                query=tc["query"],
                request_type="chat",
                context={"provider": "azure-openai"},
            )

            # Check if blocked or detected via block_reason
            detected = response.blocked

            if detected == tc["should_detect"]:
                result = "PASS"
                passed += 1
            else:
                result = "FAIL"
                failed += 1

            print(f"  Detected: {detected} (expected: {tc['should_detect']}) - {result}")

            if detected and response.block_reason:
                print(f"  Reason: {response.block_reason}")

        except Exception as e:
            # Exceptions mean PII was detected (redaction required, policy block, etc.)
            error_msg = str(e)
            detected = True

            if detected == tc["should_detect"]:
                result = "PASS"
                passed += 1
            else:
                result = "FAIL"
                failed += 1

            print(f"  Detected: {detected} (expected: {tc['should_detect']}) - {result}")
            print(f"  Reason: {error_msg}")

        print()

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    exit(main())
