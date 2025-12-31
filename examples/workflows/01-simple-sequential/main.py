#!/usr/bin/env python3
"""
Example 1: Simple Sequential Workflow - Python

This example shows the most basic AxonFlow workflow: send a query to an LLM and get a response.
"""

import os
import sys

from axonflow import AxonFlow


def main():
    # Get AxonFlow configuration from environment
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    license_key = os.getenv("AXONFLOW_LICENSE_KEY")

    if not license_key:
        print("❌ AXONFLOW_LICENSE_KEY must be set")
        sys.exit(1)

    # Create AxonFlow client
    client = AxonFlow(
        agent_url=agent_url,
        license_key=license_key,
    )

    print("✅ Connected to AxonFlow")

    # Define a simple query
    query = "What is the capital of France?"
    print(f"📤 Sending query: {query}")

    try:
        # Send query to AxonFlow
        response = client.execute_query(
            user_token="user-123",
            query=query,
            request_type="chat",
            context={
                "model": "gpt-4",
            },
        )

        # Print response
        print(f"📥 Response: {response.data}")
        print("✅ Workflow completed successfully")
    except Exception as e:
        print(f"❌ Query failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
