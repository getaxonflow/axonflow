"""
MCP Connector Example - Tests Orchestrator-to-Agent Routing

This example tests the FULL MCP connector flow:
  SDK -> Orchestrator (port 8081) -> Agent (port 8080) -> Connector

Usage:
  docker compose up -d  # Start AxonFlow
  cd examples/mcp-connectors/python
  python main.py
"""

import os
import sys
import time
import requests


def main():
    orchestrator_url = os.getenv("ORCHESTRATOR_URL", "http://localhost:8081")

    print("==============================================")
    print("MCP Connector Example - Orchestrator Routing")
    print("==============================================")
    print(f"Orchestrator URL: {orchestrator_url}\n")

    # Test 1: Query postgres connector through orchestrator
    print("Test 1: Query postgres connector via orchestrator...")

    request = {
        "request_id": f"mcp-test-{int(time.time() * 1000)}",
        "query": "SELECT 1 as test_value, 'hello' as test_message",
        "request_type": "mcp-query",
        "user": {
            "email": "test@example.com",
            "role": "user",
            "tenant_id": "default",
        },
        "client": {
            "id": "test-client",
            "tenant_id": "default",
        },
        "context": {
            "connector": "postgres",
            "params": {},
        },
    }

    try:
        response = requests.post(
            f"{orchestrator_url}/api/v1/process",
            json=request,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        result = response.json()

        if result.get("success"):
            print("SUCCESS: MCP query through orchestrator worked!")
            print(f"  Request ID: {result.get('request_id')}")
            print(f"  Processing Time: {result.get('processing_time')}")
            if result.get("data"):
                rows = result["data"].get("rows") or []
                print(f"  Rows returned: {len(rows)}")
                connector = result["data"].get("connector", "unknown")
                print(f"  Connector: {connector}")
        else:
            print(f"FAILED: {result.get('error')}")
            sys.exit(1)

        # Test 2: Query with database alias
        print("\nTest 2: Query 'database' connector (alias for postgres)...")

        request["request_id"] = f"mcp-test-{int(time.time() * 1000)}"
        request["context"]["connector"] = "database"

        response2 = requests.post(
            f"{orchestrator_url}/api/v1/process",
            json=request,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        result2 = response2.json()

        if result2.get("success"):
            print("SUCCESS: Database alias connector worked!")
        else:
            print(f"FAILED: {result2.get('error')}")
            sys.exit(1)

        print("\n==============================================")
        print("All MCP connector tests PASSED!")
        print("==============================================")

    except Exception as e:
        print(f"FAILED: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
