"""
PII Detection Demo - Hero Moment

AxonFlow detects the SSN, blocks the request,
and logs exactly what happened.
"""

import asyncio
import os

from axonflow import AxonFlow
from axonflow.exceptions import PolicyViolationError

async def main():
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:
        try:
            response = await ax.execute_query(
                user_token="demo-user",
                query="My SSN is 123-45-6789. Can you check my taxes?",
                request_type="chat",
            )
            print(response.data)
        except PolicyViolationError as e:
            print(f"PolicyViolationError: {e.message}")
            print(f"Policy: {e.policy}")
            print(f"Reason: {e.block_reason}")

if __name__ == "__main__":
    asyncio.run(main())

# Expected output:
# PolicyViolationError: Request blocked (SSN detected)
# Policy: pii-ssn
# Reason: SSN pattern detected in request
