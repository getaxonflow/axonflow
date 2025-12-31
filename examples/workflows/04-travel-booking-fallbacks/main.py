#!/usr/bin/env python3
"""
Example 4: Travel Booking with Fallbacks - Python

Demonstrates intelligent fallback patterns: try premium options first,
fall back to alternatives if unavailable.
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
    print("📤 Planning trip to Tokyo with intelligent fallbacks...\n")

    flight_option = ""
    hotel_option = ""

    try:
        # STEP 1: Try direct flights first
        print("🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...")
        flight_resp1 = client.execute_query(
            user_token="user-123",
            query="Find direct flights from San Francisco to Tokyo next month",
            request_type="chat",
            context={"model": "gpt-4"},
        )

        flight_result = str(flight_resp1.data).lower()

        if "no direct flights" in flight_result or "not available" in flight_result:
            print("⚠️  No direct flights available")
            print("📤 Step 2 (Fallback): Trying connecting flights...")

            flight_resp2 = client.execute_query(
                user_token="user-123",
                query="Find connecting flights from San Francisco to Tokyo with 1 stop",
                request_type="chat",
                context={"model": "gpt-4"},
            )

            fallback_result = str(flight_resp2.data).lower()
            if "no flights" in fallback_result:
                print("⚠️  No connecting flights available either")
                print("💡 Recommendation: Try different dates or airports")
                return

            flight_option = "Connecting flight (1 stop)"
            print("✅ Found connecting flight option")
        else:
            flight_option = "Direct flight"
            print("✅ Found direct flight")

        print()

        # STEP 2: Try 5-star hotels first
        print("🔍 Step 3: Searching for 5-star hotels in Tokyo city center...")
        hotel_resp1 = client.execute_query(
            user_token="user-123",
            query="Find 5-star hotels in Tokyo Shibuya district",
            request_type="chat",
            context={"model": "gpt-4"},
        )

        hotel_result = str(hotel_resp1.data).lower()

        if "fully booked" in hotel_result or "no availability" in hotel_result:
            print("⚠️  5-star hotels fully booked")
            print("📤 Step 4 (Fallback): Trying 4-star hotels...")

            hotel_resp2 = client.execute_query(
                user_token="user-123",
                query="Find 4-star hotels in Tokyo with good reviews",
                request_type="chat",
                context={"model": "gpt-4"},
            )

            fallback_result = str(hotel_resp2.data).lower()
            if "no availability" in fallback_result:
                print("⚠️  4-star hotels also unavailable")
                print("💡 Recommendation: Try Airbnb or alternative districts")
                return

            hotel_option = "4-star hotel (fallback)"
            print("✅ Found 4-star hotel alternative")
        else:
            hotel_option = "5-star hotel"
            print("✅ Found 5-star hotel")

        print()

        # STEP 3: Generate final itinerary
        print("📋 Generating complete itinerary with selected options...")
        itinerary_query = (
            f"Create a 7-day Tokyo itinerary with {flight_option} and {hotel_option} accommodation. "
            "Include top attractions, restaurants, and transportation tips."
        )

        itinerary_resp = client.execute_query(
            user_token="user-123",
            query=itinerary_query,
            request_type="chat",
            context={"model": "gpt-4"},
        )

        print("\n📥 Your Tokyo Itinerary:")
        print("=" * 60)
        print(itinerary_resp.data)
        print("=" * 60)
        print("\n✅ Travel booking workflow completed successfully!")
        print(f"💡 Booked: {flight_option} + {hotel_option}")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
