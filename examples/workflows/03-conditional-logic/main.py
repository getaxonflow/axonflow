#!/usr/bin/env python3
"""
Example 3: Conditional Logic Workflow - Python

Demonstrates if/else branching based on API responses.
"""

import os
import sys

from axonflow import AxonFlow


def main():
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    license_key = os.getenv("AXONFLOW_LICENSE_KEY")

    if not license_key:
        print("❌ AXONFLOW_LICENSE_KEY must be set")
        sys.exit(1)

    client = AxonFlow(
        agent_url=agent_url,
        license_key=license_key,
    )

    print("✅ Connected to AxonFlow")

    # Step 1: Search for flights
    search_query = "Find round-trip flights from New York to Paris for next week"
    print("📤 Searching for flights to Paris...")

    try:
        search_response = client.execute_query(
            user_token="user-123",
            query=search_query,
            request_type="chat",
            context={"model": "gpt-4"},
        )

        print("✅ Received search results")

        result = str(search_response.data).lower()

        # Step 2: Conditional logic based on search results
        if "no flights" in result or "not available" in result:
            # Fallback path - no flights available
            print("⚠️  No flights found for selected dates")
            print("💡 Trying alternative dates...")

            alt_query = "Find flights from New York to Paris for the following week instead"
            alt_response = client.execute_query(
                user_token="user-123",
                query=alt_query,
                request_type="chat",
                context={"model": "gpt-4"},
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

        book_response = client.execute_query(
            user_token="user-123",
            query=book_query,
            request_type="chat",
            context={"model": "gpt-4"},
        )

        print("📥 Booking Recommendation:")
        print(book_response.data)
        print("\n✅ Workflow completed successfully")
        print("💡 Tip: This example demonstrates if/else branching based on API responses")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
