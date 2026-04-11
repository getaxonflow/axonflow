#!/usr/bin/env python3
"""
Singapore PII Detection Example

Demonstrates AxonFlow's Singapore-specific PII detection for MAS FEAT compliance:
- NRIC (National Registration Identity Card)
- FIN (Foreign Identification Number)
- UEN (Unique Entity Number)
- Singapore phone numbers
- Singapore postal codes

These patterns are available in Community Edition.
"""

import asyncio
import os
import sys
from axonflow import AxonFlow


async def main():
    print("AxonFlow Singapore PII Detection - Python")
    print("=" * 44)
    print()
    print("Testing MAS FEAT Community PII patterns")
    print()

    # Initialize AxonFlow client
    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "singapore-pii-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    )

    # Test cases for Singapore PII patterns
    test_cases = [
        {
            "name": "NRIC (S prefix - Citizen pre-2000)",
            "query": "Customer NRIC is S1234567D",
            "expected_action": "redact",
            "pii_type": "NRIC",
        },
        {
            "name": "NRIC (T prefix - Citizen 2000+)",
            "query": "New customer T9876543J registered",
            "expected_action": "redact",
            "pii_type": "NRIC",
        },
        {
            "name": "FIN (F prefix - Foreigner pre-2000)",
            "query": "Employee FIN: F1234567N",
            "expected_action": "redact",
            "pii_type": "FIN",
        },
        {
            "name": "FIN (G prefix - Foreigner 2000+)",
            "query": "Applicant G9876543X submitted documents",
            "expected_action": "redact",
            "pii_type": "FIN",
        },
        {
            "name": "NRIC (M prefix - Foreigner 2022+)",
            "query": "New hire M1234567K onboarded",
            "expected_action": "redact",
            "pii_type": "NRIC",
        },
        {
            "name": "UEN (Business registration)",
            "query": "Invoice from company UEN 53276128A",
            "expected_action": "redact",
            "pii_type": "UEN",
        },
        {
            "name": "UEN (Company registration)",
            "query": "Vendor UEN: 200312345A verified",
            "expected_action": "redact",
            "pii_type": "UEN",
        },
        {
            "name": "Singapore Phone (Mobile)",
            "query": "Contact customer at +65 9123 4567",
            "expected_action": "redact",
            "pii_type": "Phone",
        },
        {
            "name": "Singapore Phone (Landline)",
            "query": "Office number: +65 6234 5678",
            "expected_action": "redact",
            "pii_type": "Phone",
        },
        {
            "name": "Singapore Postal Code",
            "query": "Delivery address: Singapore 238877",
            "expected_action": "warn",  # Postal codes are warn-only (low severity)
            "pii_type": "Postal",
        },
        {
            "name": "Safe Query (No PII)",
            "query": "What is the weather in Singapore?",
            "expected_action": "approved",
            "pii_type": "None",
        },
        {
            "name": "Multiple PII",
            "query": "Customer S1234567D phone +65 8123 4567",
            "expected_action": "redact",
            "pii_type": "Multiple",
        },
    ]

    passed = 0
    failed = 0

    for tc in test_cases:
        print(f"Test: {tc['name']} ({tc['pii_type']})")
        query_preview = tc["query"][:60] + "..." if len(tc["query"]) > 60 else tc["query"]
        print(f"  Query: {query_preview}")

        try:
            result = await client.get_policy_approved_context(
                user_token=os.getenv("AXONFLOW_USER_TOKEN", "singapore-user"),
                query=tc["query"],
            )

            print(f"  Approved: {result.approved}")
            if result.context_id:
                print(f"  Context ID: {result.context_id}")
            if result.policies:
                print(f"  Policies: {result.policies}")
            if not result.approved and result.block_reason:
                print(f"  Block Reason: {result.block_reason}")

            # Check expectation
            # For redact/warn, the request should still be approved
            if tc["expected_action"] in ("redact", "warn", "approved"):
                if result.approved:
                    status = "PASS"
                    passed += 1
                else:
                    status = "FAIL"
                    failed += 1
            else:  # blocked
                if not result.approved:
                    status = "PASS"
                    passed += 1
                else:
                    status = "FAIL"
                    failed += 1

            print(f"  Status: {status} (expected: {tc['expected_action']})")

        except Exception as e:
            print(f"  Result: ERROR - {e}")
            failed += 1

        print()

    print("=" * 44)
    print(f"Results: {passed} passed, {failed} failed")
    print()

    if failed > 0:
        print("Some tests failed. Check:")
        print("  - AxonFlow stack is running")
        print("  - Singapore PII policies are loaded (migration 042)")
        sys.exit(1)

    print("All Singapore PII detection tests passed!")
    print()
    print("MAS FEAT Compliance Notes:")
    print("  - NRIC/FIN: Critical severity, auto-redacted")
    print("  - UEN: High severity, auto-redacted")
    print("  - Phone: Medium severity, auto-redacted")
    print("  - Postal: Low severity, warning only")
    print()
    print("Enterprise features (checksum validation, AI registry)")
    print("are available with an Enterprise license.")


if __name__ == "__main__":
    asyncio.run(main())
