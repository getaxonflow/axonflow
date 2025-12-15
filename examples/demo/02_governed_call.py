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
        print(response.data)

if __name__ == "__main__":
    asyncio.run(main())
