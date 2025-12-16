"""
AxonFlow Governed Call - The Solution

Same query, but now with real-time governance:
policies, rate limits, and audit logs - all automatic.
"""

import asyncio
import os

from axonflow import AxonFlow

async def main():
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:
        response = await ax.execute_query(
            user_token="demo-user",
            query="Explain AI governance in one sentence",
            request_type="chat",
        )

        # Display the LLM response
        print("LLM Response")
        print("-" * 40)
        print(response.data)

        # Display audit information
        print("\nAudit Trail")
        print("-" * 40)
        print(f"Request ID: {response.request_id}")
        print(f"Processing Time: {response.processing_time}")

        if response.provider_info:
            print(f"Provider: {response.provider_info.provider}")
            print(f"Model: {response.provider_info.model}")

        if response.policy_info:
            print(f"Risk Score: {response.policy_info.risk_score}")
            print(f"Policies Evaluated: {len(response.policy_info.policies_evaluated)}")

if __name__ == "__main__":
    asyncio.run(main())
