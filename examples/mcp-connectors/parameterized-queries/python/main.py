#!/usr/bin/env python3
"""
Parameterized Query Example - Tests Deterministic Parameter Ordering

This example verifies that parameterized queries with multiple parameters
produce deterministic results. The Postgres connector sorts parameter keys
alphabetically before building positional arguments ($1, $2, $3...).

This is critical because Go map iteration is non-deterministic, which could
cause parameter mismatch bugs without proper key sorting.

Usage:
    docker compose up -d  # Start AxonFlow
    cd examples/mcp-connectors/parameterized-queries/python
    pip install requests
    python main.py
"""

import os
import sys

import requests


def test_parameterized_query(agent_url: str) -> bool:
    """
    Test parameterized query with multiple parameters.

    Parameters are provided with keys in non-alphabetical order:
    - zebra: "Z"
    - alpha: "A"
    - middle: "M"

    After alphabetical sorting, the order becomes:
    - alpha -> $1
    - middle -> $2
    - zebra -> $3

    Expected result: first=A, second=M, third=Z
    """
    print("Test 1: Parameterized query with multiple parameters...")
    print("  Keys provided: zebra, alpha, middle (non-alphabetical)")
    print("  Expected order after sorting: alpha, middle, zebra")

    request = {
        "connector": "axonflow_rds",
        "statement": "SELECT $1::text as first_param, $2::text as second_param, $3::text as third_param",
        "parameters": {
            "zebra": "Z",
            "alpha": "A",
            "middle": "M"
        }
    }

    try:
        response = requests.post(
            f"{agent_url}/mcp/resources/query",
            headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
            json=request,
            timeout=30
        )
        result = response.json()

        if not result.get("success"):
            print(f"  FAILED: Request unsuccessful")
            return False

        data = result.get("data", [])
        if not data:
            print("  FAILED: No data returned")
            return False

        row = data[0]
        first = row.get("first_param")
        second = row.get("second_param")
        third = row.get("third_param")

        print(f"  Result: first_param={first}, second_param={second}, third_param={third}")

        # Verify deterministic ordering
        if first == "A" and second == "M" and third == "Z":
            print("  SUCCESS: Parameters in correct alphabetical key order!")
            return True
        else:
            print(f"  FAILED: Expected first=A, second=M, third=Z")
            print(f"          Got first={first}, second={second}, third={third}")
            return False

    except requests.RequestException as e:
        print(f"  FAILED: Request error - {e}")
        return False


def test_determinism(agent_url: str, iterations: int = 10) -> bool:
    """
    Run multiple iterations to verify deterministic ordering.

    Even a single failure indicates non-deterministic behavior.
    """
    print(f"\nTest 2: Determinism test ({iterations} iterations)...")

    request = {
        "connector": "axonflow_rds",
        "statement": "SELECT $1::text as p1, $2::text as p2, $3::text as p3, $4::text as p4, $5::text as p5",
        "parameters": {
            "echo": "E",
            "alpha": "A",
            "delta": "D",
            "bravo": "B",
            "charlie": "C"
        }
    }

    # Expected order after alphabetical sort: alpha, bravo, charlie, delta, echo
    expected = {"p1": "A", "p2": "B", "p3": "C", "p4": "D", "p5": "E"}

    for i in range(iterations):
        try:
            response = requests.post(
                f"{agent_url}/mcp/resources/query",
                headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
                json=request,
                timeout=30
            )
            result = response.json()

            if not result.get("success"):
                print(f"  Iteration {i+1}: FAILED - Request unsuccessful")
                return False

            data = result.get("data", [])
            if not data:
                print(f"  Iteration {i+1}: FAILED - No data returned")
                return False

            row = data[0]
            for key, expected_val in expected.items():
                actual_val = row.get(key)
                if actual_val != expected_val:
                    print(f"  Iteration {i+1}: FAILED - {key} expected {expected_val}, got {actual_val}")
                    return False

        except requests.RequestException as e:
            print(f"  Iteration {i+1}: FAILED - {e}")
            return False

    print(f"  SUCCESS: All {iterations} iterations produced consistent results!")
    return True


def test_single_param(agent_url: str) -> bool:
    """Test single parameter (edge case)."""
    print("\nTest 3: Single parameter query...")

    request = {
        "connector": "axonflow_rds",
        "statement": "SELECT $1::text as value",
        "parameters": {
            "only_param": "SINGLE"
        }
    }

    try:
        response = requests.post(
            f"{agent_url}/mcp/resources/query",
            headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
            json=request,
            timeout=30
        )
        result = response.json()

        if not result.get("success"):
            print(f"  FAILED: Request unsuccessful")
            return False

        data = result.get("data", [])
        if not data:
            print("  FAILED: No data returned")
            return False

        value = data[0].get("value")
        if value == "SINGLE":
            print(f"  SUCCESS: Single parameter worked! value={value}")
            return True
        else:
            print(f"  FAILED: Expected 'SINGLE', got '{value}'")
            return False

    except requests.RequestException as e:
        print(f"  FAILED: Request error - {e}")
        return False


def test_empty_params(agent_url: str) -> bool:
    """Test query with no parameters (edge case)."""
    print("\nTest 4: Query with no parameters...")

    request = {
        "connector": "axonflow_rds",
        "statement": "SELECT 'no params' as result",
        "parameters": {}
    }

    try:
        response = requests.post(
            f"{agent_url}/mcp/resources/query",
            headers={"Content-Type": "application/json", "X-Tenant-ID": "default"},
            json=request,
            timeout=30
        )
        result = response.json()

        if not result.get("success"):
            print(f"  FAILED: Request unsuccessful")
            return False

        data = result.get("data", [])
        if not data:
            print("  FAILED: No data returned")
            return False

        value = data[0].get("result")
        if value == "no params":
            print(f"  SUCCESS: Empty params query worked! result={value}")
            return True
        else:
            print(f"  FAILED: Expected 'no params', got '{value}'")
            return False

    except requests.RequestException as e:
        print(f"  FAILED: Request error - {e}")
        return False


def main():
    agent_url = os.environ.get("AGENT_URL", "http://localhost:8080")

    print("=" * 60)
    print("Parameterized Query Example - Deterministic Parameter Ordering")
    print("=" * 60)
    print(f"Agent URL: {agent_url}")
    print()
    print("This example verifies fix for issue #281:")
    print("  - Go map iteration is non-deterministic")
    print("  - buildArgs() now sorts keys alphabetically")
    print("  - Parameters are assigned to $1, $2, $3... in sorted order")
    print()

    all_passed = True

    # Run all tests
    if not test_parameterized_query(agent_url):
        all_passed = False

    if not test_determinism(agent_url):
        all_passed = False

    if not test_single_param(agent_url):
        all_passed = False

    if not test_empty_params(agent_url):
        all_passed = False

    print()
    print("=" * 60)
    if all_passed:
        print("All parameterized query tests PASSED!")
        print("=" * 60)
    else:
        print("Some tests FAILED!")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
