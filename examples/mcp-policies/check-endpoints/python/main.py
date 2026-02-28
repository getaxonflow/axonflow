#!/usr/bin/env python3
"""
MCP Policy Check Endpoints Example - Python SDK

Demonstrates standalone policy-check endpoints using the AxonFlow SDK:
1. check-input: Validate MCP requests against policies without executing
2. check-output: Validate MCP response data against policies

These endpoints enable external orchestrators (LangGraph, CrewAI) to use
AxonFlow as a policy gate while managing MCP execution themselves.

VALIDATION: This example exits with code 1 if any assertion fails.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import json
import os
import sys
from typing import List

from axonflow import AxonFlow
from axonflow.exceptions import ConnectorError

failures: List[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def main() -> int:
    """Run MCP check-endpoint tests."""
    print("MCP Policy Check Endpoints - Python SDK")
    print("=" * 50)
    print()

    client = AxonFlow.sync(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=os.getenv("AXONFLOW_DEBUG", "").lower() == "true",
    )

    # ---------------------------------------------------------------
    # CHECK-INPUT TESTS
    # ---------------------------------------------------------------

    # Test 1: Clean query passes
    print("Test 1: Check-Input — Clean SQL Query")
    print("--------------------------------------")
    resp = client.mcp_check_input(
        connector_type="postgres",
        statement="SELECT name, department FROM employees WHERE id = 42",
        operation="query",
    )
    assert_check(resp.allowed, "allowed = true")
    assert_check(resp.policies_evaluated > 0, f"policies_evaluated = {resp.policies_evaluated}")
    print()

    # Test 2: SQLi blocked
    print("Test 2: Check-Input — SQL Injection Blocked")
    print("--------------------------------------------")
    resp = client.mcp_check_input(
        connector_type="postgres",
        statement="SELECT * FROM users UNION SELECT username, password FROM admin_users--",
    )
    assert_check(not resp.allowed, "allowed = false")
    assert_check(bool(resp.block_reason), f"block_reason: {resp.block_reason}")
    print()

    # Test 3: Dangerous query blocked
    print("Test 3: Check-Input — Dangerous Query (DROP TABLE)")
    print("---------------------------------------------------")
    resp = client.mcp_check_input(
        connector_type="postgres",
        statement="SELECT * FROM users; DROP TABLE users--",
    )
    assert_check(not resp.allowed, "allowed = false")
    print()

    # ---------------------------------------------------------------
    # CHECK-OUTPUT TESTS
    # ---------------------------------------------------------------

    # Test 4: Clean response passes
    print("Test 4: Check-Output — Clean Response Data")
    print("-------------------------------------------")
    resp_out = client.mcp_check_output(
        connector_type="postgres",
        response_data=[
            {"id": 1, "name": "Alice Johnson", "department": "Engineering"},
            {"id": 2, "name": "Bob Smith", "department": "Marketing"},
        ],
        row_count=2,
    )
    assert_check(resp_out.allowed, "allowed = true")
    assert_check(resp_out.policies_evaluated > 0, f"policies_evaluated = {resp_out.policies_evaluated}")
    print()

    # Test 5: PII in response — redacted
    print("Test 5: Check-Output — PII Redaction (SSN)")
    print("-------------------------------------------")
    resp_out = client.mcp_check_output(
        connector_type="postgres",
        response_data=[
            {"id": 1, "name": "Alice", "ssn": "123-45-6789"},
            {"id": 2, "name": "Bob", "ssn": "987-65-4321"},
        ],
        row_count=2,
    )
    assert_check(resp_out.allowed, "allowed = true (redacted, not blocked)")
    if resp_out.redacted_data:
        redacted_str = json.dumps(resp_out.redacted_data)
        assert_check("123-45-6789" not in redacted_str, "SSN was redacted from response")
    print()

    # Test 6: Execute-style response
    print("Test 6: Check-Output — Execute Response (Message)")
    print("--------------------------------------------------")
    resp_out = client.mcp_check_output(
        connector_type="postgres",
        message="3 rows updated",
        metadata={"query": "UPDATE users SET status = 'active' WHERE region = 'us'"},
    )
    assert_check(resp_out.allowed, "allowed = true")
    print()

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    print("=" * 50)
    if failures:
        print(f"FAILED: {len(failures)} assertion(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
