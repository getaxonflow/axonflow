#!/usr/bin/env python3
"""
Example 4: Travel Booking with Fallbacks - Python

Demonstrates intelligent fallback patterns: try premium options first,
fall back to alternatives if unavailable.
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
    print("📤 Planning trip to Tokyo with intelligent fallbacks...\n")

    flight_option = ""
    hotel_option = ""

    try:
        # STEP 1: Try direct flights first
        print("🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...")
        flight_resp1 = await client.proxy_llm_call(
            user_token="user-123",
            query="Find direct flights from San Francisco to Tokyo next month",
            request_type="chat",
            context={"provider": "openai"},
        )

        flight_result = str(flight_resp1.data).lower()

        if "no direct flights" in flight_result or "not available" in flight_result:
            print("⚠️  No direct flights available")
            print("📤 Step 2 (Fallback): Trying connecting flights...")

            flight_resp2 = await client.proxy_llm_call(
                user_token="user-123",
                query="Find connecting flights from San Francisco to Tokyo with 1 stop",
                request_type="chat",
                context={"provider": "openai"},
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
        hotel_resp1 = await client.proxy_llm_call(
            user_token="user-123",
            query="Find 5-star hotels in Tokyo Shibuya district",
            request_type="chat",
            context={"provider": "openai"},
        )

        hotel_result = str(hotel_resp1.data).lower()

        if "fully booked" in hotel_result or "no availability" in hotel_result:
            print("⚠️  5-star hotels fully booked")
            print("📤 Step 4 (Fallback): Trying 4-star hotels...")

            hotel_resp2 = await client.proxy_llm_call(
                user_token="user-123",
                query="Find 4-star hotels in Tokyo with good reviews",
                request_type="chat",
                context={"provider": "openai"},
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

        itinerary_resp = await client.proxy_llm_call(
            user_token="user-123",
            query=itinerary_query,
            request_type="chat",
            context={"provider": "openai"},
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
    asyncio.run(main())
