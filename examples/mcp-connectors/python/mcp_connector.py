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
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "demo")  # Default for self-hosted mode

    async with AxonFlow(
        agent_url=agent_url,
        client_id=client_id,
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:
        print("Testing MCP Connector Queries")
        print("-" * 60)
        print()

        # Example 1: Query PostgreSQL Connector (configured in axonflow.yaml)
        print("Example 1: Query PostgreSQL Connector")
        print("-" * 40)

        try:
            response = await client.query_connector(
                user_token="user-123",
                connector_name="postgres",  # Connector configured in config/axonflow.yaml
                operation="SELECT 1 as health_check, current_timestamp as server_time",  # Safe query
                params={},
            )

            if response.success:
                print("Status: SUCCESS")
                data_str = str(response.data)
                print(f"Data: {data_str[:200]}{'...' if len(data_str) > 200 else ''}")
            else:
                print("Status: FAILED")
                print(f"Error: {response.error}")

        except AxonFlowError as e:
            print("Status: FAILED")
            print(f"Error: {e}")

        print()

        # Example 2: Query with Policy Enforcement (SQL Injection)
        print("Example 2: Query with Policy Enforcement")
        print("-" * 40)
        print("MCP queries are policy-checked before execution.")
        print("Queries that violate policies will be blocked.")
        print()

        try:
            # This demonstrates that even connector queries go through policy checks
            response = await client.query_connector(
                user_token="user-123",
                connector_name="postgres",
                operation="SELECT * FROM users WHERE 1=1; DROP TABLE users;--",  # SQL injection attempt
                params={},
            )

            if response.success:
                print("Status: Query allowed (UNEXPECTED - should have been blocked!)")
                print(f"Response: {response.data}")
            else:
                error = response.error or ""
                if any(
                    keyword in error.lower()
                    for keyword in ["blocked", "policy", "sql injection"]
                ):
                    print("Status: BLOCKED by policy (expected behavior)")
                    print(f"Reason: {error}")
                else:
                    print("Status: FAILED")
                    print(f"Error: {error}")

        except PolicyViolationError as e:
            print("Status: BLOCKED by policy (expected behavior)")
            print(f"Reason: {e}")

        except AxonFlowError as e:
            error_str = str(e).lower()
            if any(
                keyword in error_str
                for keyword in ["blocked", "policy", "drop table", "dangerous", "sql injection"]
            ):
                print("Status: BLOCKED by policy (expected behavior)")
                print(f"Reason: {e}")
            else:
                print("Status: Error")
                print(f"Error: {e}")

    print()
    print("=" * 60)
    print("Python MCP Connector Test: COMPLETE")


if __name__ == "__main__":
    asyncio.run(main())
