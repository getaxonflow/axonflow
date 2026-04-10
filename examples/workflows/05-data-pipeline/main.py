#!/usr/bin/env python3
"""
Example 5: Data Pipeline Workflow - Python

Demonstrates a 5-stage data pipeline: Extract → Clean → Enrich → Aggregate → Report
"""

import asyncio
import os
import sys
import time

from axonflow import AxonFlow


async def main():
    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
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
    print("🔄 Starting 5-stage data pipeline for customer analytics...\n")

    start_time = time.time()

    try:
        # Stage 1: Extract
        print("📥 Stage 1/5: Extracting customer transaction data...")
        await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query="Extract customer purchase data from the last 30 days. Include customer ID, purchase amount, product categories, and timestamps. Simulate 500 customer transactions.",
            request_type="chat",
            context={"provider": "openai"},
        )
        print("✅ Stage 1 complete: Data extracted\n")

        # Stage 2: Transform (Clean & Normalize)
        print("🧹 Stage 2/5: Cleaning and normalizing data...")
        await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query="""From the extracted data above, perform the following transformations:
1. Remove duplicate transactions
2. Standardize date formats to ISO 8601
3. Normalize product category names
4. Validate all amounts are positive numbers
5. Flag any anomalies (unusually high amounts)""",
            request_type="chat",
            context={"provider": "openai"},
        )
        print("✅ Stage 2 complete: Data cleaned and normalized\n")

        # Stage 3: Enrich
        print("💎 Stage 3/5: Enriching with customer segments and lifetime value...")
        await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query="""Based on the cleaned transaction data:
1. Calculate customer lifetime value (CLV)
2. Segment customers into: VIP (CLV > $5000), Regular ($1000-$5000), New (< $1000)
3. Identify top-spending product categories per segment
4. Calculate average order value per segment""",
            request_type="chat",
            context={"provider": "openai"},
        )
        print("✅ Stage 3 complete: Data enriched with segments and metrics\n")

        # Stage 4: Aggregate
        print("📊 Stage 4/5: Aggregating insights and trends...")
        await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query="""Generate aggregated insights:
1. Total revenue by customer segment
2. Growth trends (week-over-week)
3. Top 5 products by revenue
4. Customer churn risk indicators
5. Recommended actions for each segment""",
            request_type="chat",
            context={"provider": "openai"},
        )
        print("✅ Stage 4 complete: Insights aggregated\n")

        # Stage 5: Report
        print("📈 Stage 5/5: Generating executive summary report...")
        report_resp = await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query="""Create an executive summary report with:
1. Key metrics (total revenue, customer count, avg order value)
2. Segment analysis
3. Top actionable recommendations
4. Risk alerts (if any)
Format as a concise business report.""",
            request_type="chat",
            context={"provider": "openai"},
        )

        duration = time.time() - start_time

        print("\n📊 CUSTOMER ANALYTICS REPORT")
        print("=" * 60)
        print(report_resp.data)
        print("=" * 60)
        print()
        print(f"⏱️  Pipeline completed in {duration:.1f} seconds")
        print("✅ All 5 stages executed successfully")
        print("💡 Data pipeline: Extract → Clean → Enrich → Aggregate → Report")
    except Exception as e:
        print(f"❌ Pipeline failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
