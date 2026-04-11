#!/usr/bin/env python3
"""
Example 1: Simple Sequential Workflow - Python

This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
"""

import asyncio
import os
import sys

from axonflow import AxonFlow


async def main():
    # Get AxonFlow configuration from environment
    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "workflow-example")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    # Create AxonFlow client
    client = AxonFlow(
        endpoint=agent_url,
        client_id=client_id,
        client_secret=client_secret if client_secret else None,
    )

    print("✅ Connected to AxonFlow")

    # Define a simple query
    query = "What is the capital of France?"
    print(f"📤 Sending query: {query}")

    try:
        # Send query to AxonFlow (async method)
        response = await client.proxy_llm_call(
            user_token=os.getenv("AXONFLOW_USER_TOKEN", "user-123"),
            query=query,
            request_type="chat",
            context={"provider": "openai"},
        )

        # Print response
        if hasattr(response, 'data'):
            print(f"📥 Response: {response.data}")
        elif hasattr(response, 'result'):
            print(f"📥 Response: {response.result}")
        else:
            print(f"📥 Response: {response}")
        print("✅ Workflow completed successfully")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
