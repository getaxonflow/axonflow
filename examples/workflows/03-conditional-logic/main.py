#!/usr/bin/env python3
"""
Example 3: Conditional Logic Workflow - Python

Demonstrates if/else branching based on API responses.
"""

import asyncio
import os
import sys

from axonflow import AxonFlow


async def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET")

    if not client_id or not client_secret:
        print("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
        sys.exit(1)

    client = AxonFlow(
        endpoint=agent_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    print("✅ Connected to AxonFlow")

    # Step 1: Search for flights
    search_query = "Find round-trip flights from New York to Paris for next week"
    print("📤 Searching for flights to Paris...")

    try:
        search_response = await client.execute_query(
            user_token="user-123",
            query=search_query,
            request_type="chat",
            context={"provider": "openai"},
        )

        print("✅ Received search results")

        result = str(search_response.data).lower()

        # Step 2: Conditional logic based on search results
        if "no flights" in result or "not available" in result:
            # Fallback path - no flights available
            print("⚠️  No flights found for selected dates")
            print("💡 Trying alternative dates...")

            alt_query = "Find flights from New York to Paris for the following week instead"
            alt_response = await client.execute_query(
                user_token="user-123",
                query=alt_query,
                request_type="chat",
                context={"provider": "openai"},
            )

            print("📥 Alternative Options:")
            print(alt_response.data)
            print("✅ Workflow completed with fallback")
            return

        # Success path - flights found
        print("💡 Flights found! Analyzing best option...")
        print(search_response.data)

        # Step 3: Proceed to booking recommendation
        book_query = "Based on the search results above, what would be the recommended booking?"
        print("\n📤 Getting booking recommendation...")

        book_response = await client.execute_query(
            user_token="user-123",
            query=book_query,
            request_type="chat",
            context={"provider": "openai"},
        )

        print("📥 Booking Recommendation:")
        print(book_response.data)
        print("\n✅ Workflow completed successfully")
        print("💡 Tip: This example demonstrates if/else branching based on API responses")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
