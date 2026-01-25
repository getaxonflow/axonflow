#!/usr/bin/env python3
"""
MCP Audit Logging Example - Python SDK

This example demonstrates how MCP query operations are automatically
audited by AxonFlow. Every MCP query/execute operation is logged to
the mcp_query_audits table with policy evaluation results.

What gets audited:
  - Request phase: SQLi detection, PII blocking
  - Response phase: PII redaction
  - Exfiltration checks: Row/volume limits
  - Final result: success/failure, duration

Usage:
    docker compose up -d  # Start AxonFlow
    cd examples/mcp-audit/python
    pip install axonflow
    python main.py
"""

import os
import asyncio
from axonflow import AxonFlow


async def main():
    # Get configuration from environment
    agent_url = os.getenv("AGENT_URL", "http://localhost:8080")
    client_id = os.getenv("CLIENT_ID", "demo-client")
    client_secret = os.getenv("CLIENT_SECRET", "demo-secret")

    print("==============================================")
    print("MCP Audit Logging Example - Python SDK")
    print("==============================================")
    print(f"Agent URL: {agent_url}")
    print(f"Client ID: {client_id}")
    print()

    # Create AxonFlow client
    client = AxonFlow(
        endpoint=agent_url,
        client_id=client_id,
        client_secret=client_secret,
    )

    # Test 1: Simple query (creates audit entry)
    print("Test 1: Execute simple MCP query...")
    print("----------------------------------------------")

    try:
        result = await client.mcp_query(
            connector="postgres",
            statement="SELECT 1 as test_value, 'hello' as test_message",
        )
        print("SUCCESS: Query executed")
        print(f"  Success: {result.success}")
        if result.policy_info:
            print(f"  Policies evaluated: {result.policy_info.policies_evaluated}")
            print(f"  Blocked: {result.policy_info.blocked}")
            print(f"  Processing time: {result.policy_info.processing_time_ms}ms")
    except Exception as e:
        print(f"Query error (expected if postgres not configured): {e}")
    print()

    # Test 2: Query that may trigger PII detection
    print("Test 2: Execute query with potential PII fields...")
    print("----------------------------------------------")

    try:
        result = await client.mcp_query(
            connector="postgres",
            statement="SELECT email, phone, name FROM users LIMIT 5",
        )
        print("SUCCESS: Query executed")
        print(f"  Success: {result.success}")
        print(f"  Redacted: {result.redacted}")
        if result.policy_info:
            print(f"  Policies evaluated: {result.policy_info.policies_evaluated}")
        if result.redacted_fields:
            print(f"  PII REDACTED! Fields: {result.redacted_fields}")
    except Exception as e:
        print(f"Query error: {e}")
    print()

    # Test 3: Query with SQLi pattern (should be blocked)
    print("Test 3: Execute query with SQLi pattern (should be blocked)...")
    print("----------------------------------------------")

    try:
        result = await client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM users; DROP TABLE users;--",
        )
        print("Note: SQLi detection may not be enabled")
    except Exception as e:
        print(f"Query blocked as expected: {e}")
        print("SUCCESS: SQLi attempt was blocked and audit logged")
    print()

    # Test 4: Execute (INSERT) operation
    print("Test 4: Execute INSERT operation...")
    print("----------------------------------------------")

    try:
        result = await client.mcp_execute(
            connector="postgres",
            statement="INSERT INTO audit_test (name) VALUES ('test')",
        )
        print("SUCCESS: Execute completed")
        print(f"  Success: {result.success}")
    except Exception as e:
        print(f"Execute error (expected if table doesn't exist): {e}")
    print()

    print("==============================================")
    print("MCP Audit Logging Tests Complete!")
    print("==============================================")
    print()
    print("All MCP operations above have been logged to the")
    print("mcp_query_audits table. Each entry includes:")
    print("  - audit_id: Unique identifier")
    print("  - tenant_id, client_id, user_id: Who made the request")
    print("  - connector_name, operation: What was requested")
    print("  - request_blocked, request_block_reason: If request was blocked")
    print("  - response_redacted, response_redacted_fields: If PII was redacted")
    print("  - exfil_exceeded, exfil_limit_type: If exfiltration limit hit")
    print("  - success, error_message: Final result")
    print("  - duration_ms: How long it took")

    await client.close()


if __name__ == "__main__":
    asyncio.run(main())
