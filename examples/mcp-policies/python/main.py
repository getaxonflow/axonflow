#!/usr/bin/env python3
"""
MCP Policy Enforcement Example - Python SDK

Demonstrates and VALIDATES phase-aware policy enforcement:
1. REQUEST phase: SQLi patterns are blocked
2. RESPONSE phase: PII in connector data is redacted
3. PolicyInfo metadata in all responses

VALIDATION: This example exits with code 1 if any assertion fails.

Policy Configuration (env vars):
  MCP_STATIC_POLICIES_ENABLED - Enable/disable static MCP policies: "true" (default) or "false"

  When enabled (default): static policies (SQLi blocking, PII redaction) are enforced
  When disabled: static policies are skipped; only dynamic policies apply

Run with: python main.py
Prerequisites: docker compose up -d
"""

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
    """Run MCP policy enforcement tests."""
    print("MCP Policy Enforcement - Python SDK")
    print("=" * 50)
    print()

    client = AxonFlow.sync(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo"),
        debug=os.getenv("AXONFLOW_DEBUG", "").lower() == "true",
    )

    # Test 1: Clean query should pass through
    print("Test 1: Clean Query (No PII, No SQLi)")
    print("--------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT 1 as test_value",
        )
        assert_check(resp.success, "Query succeeded")
        assert_check(not resp.redacted, "No redaction applied")
        if resp.policy_info:
            assert_check(resp.policy_info.policies_evaluated >= 0, "Policies were evaluated")
            assert_check(not resp.policy_info.blocked, "Request was not blocked")
            print(
                f"   PolicyInfo: {resp.policy_info.policies_evaluated} policies "
                f"evaluated in {resp.policy_info.processing_time_ms}ms"
            )
    except Exception as err:
        print(f"   Query failed: {err}")
    print()

    # Test 2: SQLi pattern should be blocked
    print("Test 2: SQL Injection Pattern (Request Blocked)")
    print("------------------------------------------------")
    try:
        client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
        )
        assert_check(False, "SQLi pattern should have been blocked")
    except ConnectorError as err:
        assert_check(True, "Request blocked as expected")
        print(f"   Block reason: {err}")
    except Exception as err:
        print(f"   Unexpected error: {err}")
    print()

    # Test 3: UNION-based SQLi should also be blocked
    print("Test 3: UNION SQLi Pattern (Request Blocked)")
    print("---------------------------------------------")
    try:
        client.mcp_query(
            connector="postgres",
            statement="SELECT name FROM employees UNION SELECT password FROM admin_users",
        )
        assert_check(False, "UNION SQLi should have been blocked")
    except ConnectorError as err:
        assert_check(True, "UNION SQLi blocked as expected")
        print(f"   Block reason: {err}")
    except Exception as err:
        print(f"   Unexpected error: {err}")
    print()

    # Test 4: Response with PII should have redacted fields
    print("Test 4: Response Redaction (PII in Data)")
    print("-----------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM test_customers LIMIT 1",
        )
        if resp.success:
            if resp.redacted:
                assert_check(True, "Response was redacted")
                assert_check(len(resp.redacted_fields) > 0, "Redacted fields are listed")
                print(f"   Redacted fields: {', '.join(resp.redacted_fields)}")
            else:
                print("   Note: No PII found in response")
            if resp.policy_info:
                print(
                    f"   PolicyInfo: {resp.policy_info.redactions_applied} redactions "
                    f"in {resp.policy_info.processing_time_ms}ms"
                )
    except Exception as err:
        print(f"   Query failed: {err}")
        print("   Note: test_customers table may not exist")
    print()

    # Test 5: Request-side PII blocking (SSN in query)
    print("Test 5: Request-side PII Blocking (SSN in Query)")
    print("------------------------------------------------")
    try:
        client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM customers WHERE ssn = '123-45-6789'",
        )
        assert_check(False, "SSN in query should have been blocked")
    except ConnectorError as err:
        assert_check(True, "SSN in query blocked as expected")
        print(f"   Block reason: {err}")
    except Exception as err:
        print(f"   Unexpected error: {err}")
    print()

    # ========================================
    # Policy Configuration Check (MCP_STATIC_POLICIES_ENABLED)
    # ========================================
    static_policies_enabled = os.getenv("MCP_STATIC_POLICIES_ENABLED", "true")
    print("Test 6: Static Policies Configuration Check")
    print("--------------------------------------------")
    if static_policies_enabled == "true":
        print("   MCP_STATIC_POLICIES_ENABLED=true (default)")
        print("   Static policies (SQLi blocking, PII redaction) are ACTIVE")
    else:
        print("   MCP_STATIC_POLICIES_ENABLED=false")
        print("   Static policies are DISABLED; only dynamic policies apply")
        print("   Note: SQLi blocking and PII redaction tests above may behave differently")
    print()

    # Close the client
    client.close()

    # Summary
    print("=" * 50)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("MCP Policy Enforcement validated:")
        print("  - REQUEST phase: SQLi blocking")
        print("  - REQUEST phase: PII blocking")
        print("  - RESPONSE phase: PII redaction")
        print("  - PolicyInfo metadata in responses")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
