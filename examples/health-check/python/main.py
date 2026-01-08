#!/usr/bin/env python3
"""
Health Check Example - Python

Demonstrates how to check the health of AxonFlow Agent and Orchestrator services.
This is essential for monitoring and ensuring your governance infrastructure is running.

Usage:
    python main.py

Environment:
    AXONFLOW_AGENT_URL     - Agent URL (default: http://localhost:8080)
    AXONFLOW_CLIENT_ID     - OAuth2 client ID (optional for community mode)
    AXONFLOW_CLIENT_SECRET - OAuth2 client secret (optional for community mode)
"""

import asyncio
import os
from axonflow import AxonFlow


async def main():
    # Initialize client (credentials optional for community mode)
    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("AXONFLOW_CLIENT_ID", "")
    client_secret = os.getenv("AXONFLOW_CLIENT_SECRET", "")

    client = AxonFlow(
        endpoint=agent_url,
        client_id=client_id if client_id else None,
        client_secret=client_secret if client_secret else None,
    )

    print("=== AxonFlow Health Check Example ===\n")

    # 1. Check Agent health
    print("1. Checking Agent health...")
    try:
        agent_healthy = await client.health_check()
        if agent_healthy:
            print("   Agent Status: HEALTHY")
        else:
            print("   Agent Status: UNHEALTHY")
    except Exception as e:
        print(f"   Agent health check failed: {e}")
        agent_healthy = False

    # 2. Check Orchestrator health
    print("\n2. Checking Orchestrator health...")
    try:
        orch_healthy = await client.orchestrator_health_check()
        if orch_healthy:
            print("   Orchestrator Status: HEALTHY")
        else:
            print("   Orchestrator Status: UNHEALTHY")
    except Exception as e:
        print(f"   Orchestrator health check failed: {e}")
        orch_healthy = False

    # 3. Summary
    print("\n=== Health Check Summary ===")
    print(f"   Agent: {'HEALTHY' if agent_healthy else 'UNHEALTHY'}")
    print(f"   Orchestrator: {'HEALTHY' if orch_healthy else 'UNHEALTHY'}")

    # Return success if both are healthy
    return agent_healthy and orch_healthy


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
