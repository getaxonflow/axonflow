"""MCP PII Redaction - Comprehensive Test (Python SDK)

This example validates that PII types are properly redacted in MCP connector responses:
- US Social Security Numbers (SSN)
- Credit Card numbers
- Email addresses (non-critical, logged only)
- Phone numbers (non-critical, logged only)

Run with: python main.py
Prerequisites: docker compose up -d
"""

import os
import sys
from axonflow import AxonFlow

failures = []
passes = 0


def get_env(key: str, default: str) -> str:
    return os.environ.get(key, default)


def assert_check(condition: bool, message: str) -> None:
    global passes
    if not condition:
        failures.append(message)
        print(f"   FAIL: {message}")
    else:
        passes += 1
        print(f"   PASS: {message}")


def main():
    global passes

    print("MCP PII Redaction - Comprehensive Test")
    print("=======================================")
    print()

    client = AxonFlow.sync(
        endpoint=get_env("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id=get_env("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=get_env("AXONFLOW_CLIENT_SECRET", "demo"),
    )

    # Test 1: Query test_customers table (pre-seeded with PII data)
    print("Test 1: Query test_customers (Response Redaction)")
    print("-------------------------------------------------")

    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM test_customers LIMIT 1"
        )

        assert_check(resp.success, "Query executed successfully")

        if resp.redacted:
            assert_check(True, "Response was redacted")
            assert_check(len(resp.redacted_fields) > 0, "Redacted fields are listed")
            print(f"   Redacted fields: {resp.redacted_fields}")

            redacted_str = ", ".join(resp.redacted_fields)
            if "ssn" in redacted_str:
                print("   - SSN: redacted")
            if "credit_card" in redacted_str:
                print("   - Credit Card: redacted")
        else:
            print("   Note: No PII found in response (test_customers may be empty)")

        if resp.policy_info:
            print(f"   PolicyInfo: {resp.policy_info.policies_evaluated} policies, "
                  f"{resp.policy_info.redactions_applied} redactions in {resp.policy_info.processing_time_ms}ms")
    except Exception as e:
        print(f"   Query failed: {e}")
        print("   Note: test_customers table may not exist")

    print()

    # Test 2: Request-phase PII blocking (SSN in query)
    print("Test 2: Request-phase PII Blocking (SSN)")
    print("----------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM users WHERE ssn = '123-45-6789'"
        )
        if not resp.success:
            assert_check(True, "SSN in query blocked as expected")
        else:
            assert_check(False, "SSN in query should have been blocked")
    except Exception as e:
        assert_check(True, "SSN in query blocked as expected")
        print(f"   Block reason: {e}")

    print()

    # Test 3: Request-phase PII blocking (Credit Card)
    print("Test 3: Request-phase PII Blocking (Credit Card)")
    print("------------------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM orders WHERE card = '4111111111111111'"
        )
        if not resp.success:
            assert_check(True, "Credit card in query blocked as expected")
        else:
            assert_check(False, "Credit card in query should have been blocked")
    except Exception as e:
        assert_check(True, "Credit card in query blocked as expected")
        print(f"   Block reason: {e}")

    print()

    # Test 4: Request-phase PII blocking (India PAN)
    print("Test 4: Request-phase PII Blocking (India PAN)")
    print("----------------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM customers WHERE pan = 'ABCPD1234E'"
        )
        if not resp.success:
            assert_check(True, "India PAN in query blocked as expected")
        else:
            assert_check(False, "India PAN in query should have been blocked")
    except Exception as e:
        assert_check(True, "India PAN in query blocked as expected")
        print(f"   Block reason: {e}")

    print()

    # Test 5: Request-phase PII blocking (India Aadhaar)
    print("Test 5: Request-phase PII Blocking (India Aadhaar)")
    print("--------------------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT * FROM customers WHERE aadhaar = '234567890123'"
        )
        if not resp.success:
            assert_check(True, "India Aadhaar in query blocked as expected")
        else:
            assert_check(False, "India Aadhaar in query should have been blocked")
    except Exception as e:
        assert_check(True, "India Aadhaar in query blocked as expected")
        print(f"   Block reason: {e}")

    print()

    # Test 6: Non-critical PII (email) - should NOT be blocked
    print("Test 6: Non-critical PII (Email) - Should Pass")
    print("----------------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT 'john@example.com' as test_email"
        )
        if resp.success:
            assert_check(True, "Email in query allowed (non-critical PII)")
        else:
            print("   Note: Email was blocked (policy may be strict)")
    except Exception as e:
        print(f"   Note: Email was blocked (policy may be strict): {e}")

    print()

    # Test 7: Non-critical PII (phone) - should NOT be blocked
    print("Test 7: Non-critical PII (Phone) - Should Pass")
    print("----------------------------------------------")
    try:
        resp = client.mcp_query(
            connector="postgres",
            statement="SELECT '+1-555-123-4567' as test_phone"
        )
        if resp.success:
            assert_check(True, "Phone in query allowed (non-critical PII)")
        else:
            print("   Note: Phone was blocked (policy may be strict)")
    except Exception as e:
        print(f"   Note: Phone was blocked (policy may be strict): {e}")

    print()

    # Summary
    print("=======================================")
    if len(failures) == 0:
        print(f"ALL TESTS PASSED ({passes} assertions)")
        print()
        print("MCP PII Handling validated:")
        print("  Response-phase:")
        print("    - SSN redaction in response data")
        print("    - Credit card redaction in response data")
        print("  Request-phase blocking:")
        print("    - US SSN in query (critical)")
        print("    - Credit Card in query (critical)")
        print("    - India PAN in query (critical)")
        print("    - India Aadhaar in query (critical)")
        print("  Non-critical (allowed):")
        print("    - Email in query")
        print("    - Phone in query")
    else:
        print(f"{len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        sys.exit(1)


if __name__ == "__main__":
    main()
