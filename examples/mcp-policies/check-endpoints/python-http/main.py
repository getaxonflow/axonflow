#!/usr/bin/env python3
"""
MCP Policy Check Endpoints Example - Python (HTTP)

Demonstrates and VALIDATES standalone policy-check endpoints:
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
from typing import Any, List

import requests

failures: List[str] = []

AGENT_URL = os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080")


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


def check_input(body: dict[str, Any]) -> requests.Response:
    """POST to check-input endpoint."""
    return requests.post(
        f"{AGENT_URL}/api/v1/mcp/check-input",
        json=body,
        timeout=10,
    )


def check_output(body: dict[str, Any]) -> requests.Response:
    """POST to check-output endpoint."""
    return requests.post(
        f"{AGENT_URL}/api/v1/mcp/check-output",
        json=body,
        timeout=10,
    )


def main() -> int:
    """Run MCP check-endpoint tests."""
    print("MCP Policy Check Endpoints - Python (HTTP)")
    print("=" * 50)
    print()

    # ---------------------------------------------------------------
    # CHECK-INPUT TESTS
    # ---------------------------------------------------------------

    # Test 1: Clean query passes
    print("Test 1: Check-Input — Clean SQL Query")
    print("--------------------------------------")
    resp = check_input({
        "connector_type": "postgres",
        "statement": "SELECT name, department FROM employees WHERE id = 42",
        "operation": "query",
    })
    data = resp.json()
    assert_check(resp.status_code == 200, f"HTTP 200 (got {resp.status_code})")
    assert_check(data.get("allowed") is True, "allowed = true")
    assert_check(data.get("policies_evaluated", 0) > 0, "Policies were evaluated")
    print()

    # Test 2: SQLi blocked
    print("Test 2: Check-Input — SQL Injection Blocked")
    print("--------------------------------------------")
    resp = check_input({
        "connector_type": "postgres",
        "statement": "SELECT * FROM users UNION SELECT username, password FROM admin_users--",
    })
    data = resp.json()
    assert_check(resp.status_code == 403, f"HTTP 403 (got {resp.status_code})")
    assert_check(data.get("allowed") is False, "allowed = false")
    assert_check(bool(data.get("block_reason")), f"block_reason present: {data.get('block_reason', '')}")
    print()

    # Test 3: Dangerous query blocked
    print("Test 3: Check-Input — Dangerous Query (DROP TABLE)")
    print("---------------------------------------------------")
    resp = check_input({
        "connector_type": "postgres",
        "statement": "SELECT * FROM users; DROP TABLE users--",
    })
    data = resp.json()
    assert_check(resp.status_code == 403, f"HTTP 403 (got {resp.status_code})")
    assert_check(data.get("allowed") is False, "allowed = false")
    print()

    # Test 4: Validation error — missing connector_type
    print("Test 4: Check-Input — Missing connector_type")
    print("---------------------------------------------")
    resp = check_input({
        "statement": "SELECT 1",
    })
    assert_check(resp.status_code == 400, f"HTTP 400 (got {resp.status_code})")
    print()

    # ---------------------------------------------------------------
    # CHECK-OUTPUT TESTS
    # ---------------------------------------------------------------

    # Test 5: Clean response passes
    print("Test 5: Check-Output — Clean Response Data")
    print("-------------------------------------------")
    resp = check_output({
        "connector_type": "postgres",
        "response_data": [
            {"id": 1, "name": "Alice Johnson", "department": "Engineering"},
            {"id": 2, "name": "Bob Smith", "department": "Marketing"},
        ],
        "row_count": 2,
    })
    data = resp.json()
    assert_check(resp.status_code == 200, f"HTTP 200 (got {resp.status_code})")
    assert_check(data.get("allowed") is True, "allowed = true")
    print()

    # Test 6: PII in response — redacted
    print("Test 6: Check-Output — PII Redaction (SSN)")
    print("-------------------------------------------")
    resp = check_output({
        "connector_type": "postgres",
        "response_data": [
            {"id": 1, "name": "Alice", "ssn": "123-45-6789"},
            {"id": 2, "name": "Bob", "ssn": "987-65-4321"},
        ],
        "row_count": 2,
    })
    data = resp.json()
    # PII redaction returns 200 (redact action, not block)
    assert_check(resp.status_code == 200, f"HTTP 200 (got {resp.status_code})")
    assert_check(data.get("allowed") is True, "allowed = true (redacted, not blocked)")
    if data.get("redacted_data"):
        redacted = json.dumps(data["redacted_data"])
        assert_check("123-45-6789" not in redacted, "SSN 123-45-6789 was redacted from response")
    assert_check(data.get("policies_evaluated", 0) > 0, "Policies were evaluated")
    print()

    # Test 7: Execute-style response (message only)
    print("Test 7: Check-Output — Execute Response (Message)")
    print("--------------------------------------------------")
    resp = check_output({
        "connector_type": "postgres",
        "message": "3 rows updated",
        "metadata": {
            "query": "UPDATE users SET status = 'active' WHERE region = 'us'",
        },
    })
    data = resp.json()
    assert_check(resp.status_code == 200, f"HTTP 200 (got {resp.status_code})")
    assert_check(data.get("allowed") is True, "allowed = true")
    print()

    # Test 8: Validation error — missing both response_data and message
    print("Test 8: Check-Output — Missing response_data and message")
    print("---------------------------------------------------------")
    resp = check_output({
        "connector_type": "postgres",
    })
    assert_check(resp.status_code == 400, f"HTTP 400 (got {resp.status_code})")
    print()

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------
    print("=" * 50)
    total = len(failures)
    if total > 0:
        print(f"FAILED: {total} assertion(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
