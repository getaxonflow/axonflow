"""
Part 2.1: PII Detection Suite

AxonFlow detects and blocks PII across multiple jurisdictions:
- US: Social Security Numbers (SSN), Credit Cards
- India: PAN (Permanent Account Number), Aadhaar

Each pattern triggers the appropriate policy for blocking or redaction.
"""

import asyncio
import os

from axonflow import AxonFlow


# PII test cases with expected outcomes
PII_TESTS = [
    {
        "name": "US Social Security Number",
        "query": "Customer SSN is 123-45-6789 for verification",
        "pattern": "SSN",
        "expected": "blocked",
    },
    {
        "name": "Credit Card (Visa)",
        "query": "Charge card 4111-1111-1111-1111 for $99",
        "pattern": "Credit Card",
        "expected": "blocked",
    },
    {
        "name": "Indian PAN",
        "query": "Customer PAN is ABCDE1234F for tax records",
        "pattern": "PAN",
        "expected": "flagged",  # May be flagged for redaction rather than blocked
    },
    {
        "name": "Indian Aadhaar",
        "query": "Verify Aadhaar number 2345 6789 0123",
        "pattern": "Aadhaar",
        "expected": "blocked",
    },
]


async def test_pii_detection(client: AxonFlow) -> None:
    """Test PII detection for multiple patterns."""
    print("PII Detection Tests")
    print("=" * 60)
    print()

    passed = 0
    total = len(PII_TESTS)

    for test in PII_TESTS:
        print(f"Test: {test['name']}")
        print(f"  Query: \"{test['query'][:50]}...\"")

        try:
            # Use pre-check to test policy enforcement
            ctx = await client.get_policy_approved_context(
                user_token="demo-user",
                query=test["query"],
            )

            if not ctx.approved:
                print(f"  Result: BLOCKED")
                print(f"  Reason: {ctx.block_reason}")
                if ctx.policies:
                    print(f"  Policy: {ctx.policies[0] if ctx.policies else 'N/A'}")
                passed += 1
            else:
                # Check if flagged (policies triggered but not blocked)
                if ctx.policies and len(ctx.policies) > 0:
                    print(f"  Result: FLAGGED")
                    print(f"  Policy: {ctx.policies[0]}")
                    passed += 1
                else:
                    print(f"  Result: ALLOWED (unexpected)")
                    print(f"  Expected: {test['expected']}")

        except Exception as e:
            print(f"  Result: ERROR - {e}")

        print()

    print("-" * 60)
    print(f"Results: {passed}/{total} PII patterns detected")
    print()


async def test_safe_query(client: AxonFlow) -> None:
    """Test that safe queries pass through."""
    print("Safe Query Test")
    print("=" * 60)
    print()

    query = "What is the status of open support tickets?"

    print(f"Query: \"{query}\"")

    ctx = await client.get_policy_approved_context(
        user_token="demo-user",
        query=query,
    )

    if ctx.approved:
        print(f"Result: ALLOWED (expected)")
        print(f"Context ID: {ctx.context_id}")
        print(f"Latency: {ctx.processing_time_ms}ms" if hasattr(ctx, 'processing_time_ms') else "")
    else:
        print(f"Result: BLOCKED (unexpected)")
        print(f"Reason: {ctx.block_reason}")

    print()


async def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:
        await test_pii_detection(client)
        await test_safe_query(client)


if __name__ == "__main__":
    asyncio.run(main())
