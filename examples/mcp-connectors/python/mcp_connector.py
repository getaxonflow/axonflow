#!/usr/bin/env python3
"""
AxonFlow MCP Connector Example - Python

Demonstrates how to query MCP (Model Context Protocol) connectors
through AxonFlow with policy governance.

MCP connectors allow AI applications to securely interact with
external systems like databases, APIs, and more.

Prerequisites:
- AxonFlow running with connectors enabled (docker-compose up -d)
- PostgreSQL connector configured in config/axonflow.yaml

Usage:
  export AXONFLOW_AGENT_URL=http://localhost:8080
  python mcp_connector.py
"""

import os
import asyncio
from axonflow import AxonFlow
from axonflow.exceptions import PolicyViolationError, AxonFlowError


async def main():
    print("AxonFlow MCP Connector Example - Python")
    print("=" * 60)
    print()

    # Initialize AxonFlow client
    # Note: client_secret is required by SDK validation but not used in self-hosted mode
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=client_id,
        client_secret=client_secret,
    ) as client:
        print("Testing MCP Connector Queries")
        print("-" * 60)
        print()

        # Example 1: Health check query
        print("Example 1: PostgreSQL Health Check")
        print("-" * 40)

        try:
            response = await client.query_connector(
                user_token="user-123",
                connector_name="postgres",
                operation="SELECT 1 as health_check, current_timestamp as server_time",
                params={},
            )

            if response.success:
                print("Status: SUCCESS")
                print(f"Data: {response.data}")
            else:
                print("Status: FAILED")
                print(f"Error: {response.error}")

        except AxonFlowError as e:
            print("Status: FAILED")
            print(f"Error: {e}")

        print()

        # Example 2: Query actual database table
        print("Example 2: Query Database Table")
        print("-" * 40)

        try:
            # Query the static_policies table (always exists in AxonFlow)
            response = await client.query_connector(
                user_token="user-123",
                connector_name="postgres",
                operation="SELECT id, name, category FROM static_policies LIMIT 3",
                params={},
            )

            if response.success:
                print("Status: SUCCESS")
                if response.data:
                    print(f"Found {len(response.data) if isinstance(response.data, list) else 1} policies:")
                    for row in (response.data if isinstance(response.data, list) else [response.data]):
                        print(f"  - {row.get('name', 'N/A')} ({row.get('category', 'N/A')})")
                else:
                    print("No data returned")
            else:
                print("Status: FAILED")
                print(f"Error: {response.error}")

        except AxonFlowError as e:
            print("Status: FAILED")
            print(f"Error: {e}")

        print()

        # Example 3: SQL Injection Detection
        print("Example 3: SQL Injection Detection")
        print("-" * 40)
        print("Demonstrating that malicious queries are handled safely.")
        print()

        try:
            response = await client.query_connector(
                user_token="user-123",
                connector_name="postgres",
                operation="SELECT * FROM users; DROP TABLE users;--",
                params={},
            )

            if response.success:
                print("Status: Query executed")
                print(f"Response: {response.data}")
            else:
                print("Status: Query failed (expected for malicious input)")
                print(f"Reason: {response.error}")

        except PolicyViolationError as e:
            print("Status: BLOCKED by policy (expected behavior)")
            print(f"Reason: {e}")

        except AxonFlowError as e:
            error_str = str(e).lower()
            if "blocked by policy" in error_str or "sql injection" in error_str:
                print("Status: BLOCKED by policy (expected behavior)")
                print(f"Reason: {e}")
            elif "query execution failed" in error_str or "does not exist" in error_str:
                print("Status: Query failed at database level")
                print(f"Note: Table 'users' doesn't exist (expected)")
                print(f"Error: {e}")
            else:
                print("Status: Error")
                print(f"Error: {e}")

    print()
    print("=" * 60)
    print("Python MCP Connector Test: COMPLETE")


if __name__ == "__main__":
    asyncio.run(main())
