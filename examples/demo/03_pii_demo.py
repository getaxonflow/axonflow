"""
PII Detection Demo - Hero Moment

AxonFlow detects the SSN, blocks the request,
and logs exactly what happened - full audit trail.
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
            print("Request Blocked")
            print("=" * 40)
            print(f"Status: BLOCKED")
            print(f"Reason: {e.block_reason}")
            print(f"Policy: {e.policy}")

            print("\nAudit Trail")
            print("-" * 40)
            print(f"Detection: PII detected in input")
            print(f"Action: Request blocked before LLM call")
            print(f"Logged: Yes (immutable audit record created)")

if __name__ == "__main__":
    asyncio.run(main())

# Expected output:
# Request Blocked
# ========================================
# Status: BLOCKED
# Reason: US Social Security Number pattern detected
# Policy: pii_ssn_detection
#
# Audit Trail
# ----------------------------------------
# Detection: PII detected in input
# Action: Request blocked before LLM call
# Logged: Yes (immutable audit record created)
