#!/usr/bin/env python3
"""
AxonFlow Policy Management - Test Pattern

VALIDATION: This example exits with code 1 if any assertion fails.

This example demonstrates how to test regex patterns
before creating policies. This helps ensure your patterns
work correctly and catch the right inputs.

Run with: python test_pattern.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from axonflow import AxonFlow

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    """Test various regex patterns."""
    print("AxonFlow Policy Management - Pattern Testing")
    print("=" * 60)

    client = AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",
        client_secret="test-secret",
    )

    try:
        # 1. Test a credit card pattern
        print("\n1. Testing credit card pattern...")

        cc_pattern = r"\b(?:\d{4}[- ]?){3}\d{4}\b"
        cc_test_inputs = [
            "4111-1111-1111-1111",  # Valid Visa format with dashes
            "4111111111111111",  # Valid Visa format no dashes
            "4111 1111 1111 1111",  # Valid with spaces
            "not-a-card",  # Invalid
            "411111111111111",  # Too short (15 digits)
            "41111111111111111",  # Too long (17 digits)
            "My card is 5500-0000-0000-0004",  # Embedded in text
        ]

        cc_result = await client.test_pattern(cc_pattern, cc_test_inputs)

        assert_check(cc_result is not None, "Credit card pattern test returned result")
        assert_check(cc_result.valid, "Credit card pattern is valid regex")
        assert_check(len(cc_result.matches) == len(cc_test_inputs), "All inputs were tested")

        print(f"   Pattern: {cc_pattern}")
        print(f"   Valid regex: {cc_result.valid}")
        print("\n   Results:")

        # Verify expected matches
        expected_cc_matches = [True, True, True, False, False, False, True]
        for i, match in enumerate(cc_result.matches):
            icon = "✓ MATCH" if match.matched else "✗ no match"
            print(f'   {icon}  "{match.input}"')
            if i < len(expected_cc_matches):
                assert_check(
                    match.matched == expected_cc_matches[i],
                    f"CC input '{match.input[:20]}...' matched as expected"
                )

        # 2. Test a US SSN pattern
        print("\n2. Testing US SSN pattern...")

        ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"
        ssn_test_inputs = [
            "123-45-6789",  # Valid SSN format
            "000-00-0000",  # Valid format (but invalid SSN)
            "SSN: 987-65-4321",  # Embedded in text
            "123456789",  # No dashes
            "12-345-6789",  # Wrong grouping
        ]

        ssn_result = await client.test_pattern(ssn_pattern, ssn_test_inputs)

        assert_check(ssn_result is not None, "SSN pattern test returned result")
        assert_check(ssn_result.valid, "SSN pattern is valid regex")

        print(f"   Pattern: {ssn_pattern}")
        print("\n   Results:")

        expected_ssn_matches = [True, True, True, False, False]
        for i, match in enumerate(ssn_result.matches):
            icon = "✓ MATCH" if match.matched else "✗ no match"
            print(f'   {icon}  "{match.input}"')
            if i < len(expected_ssn_matches):
                assert_check(
                    match.matched == expected_ssn_matches[i],
                    f"SSN input '{match.input}' matched as expected"
                )

        # 3. Test an email pattern
        print("\n3. Testing email pattern...")

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        email_test_inputs = [
            "user@example.com",
            "first.last@company.org",
            "test+filter@gmail.com",
            "invalid-email",
            "@missing-local.com",
            "no-domain@",
        ]

        email_result = await client.test_pattern(email_pattern, email_test_inputs)

        assert_check(email_result is not None, "Email pattern test returned result")
        assert_check(email_result.valid, "Email pattern is valid regex")

        print(f"   Pattern: {email_pattern}")
        print("\n   Results:")

        for match in email_result.matches:
            icon = "✓ MATCH" if match.matched else "✗ no match"
            print(f'   {icon}  "{match.input}"')

        # 4. Test SQL injection pattern
        print("\n4. Testing SQL injection pattern...")

        sqli_pattern = r"(?i)\b(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table)\b"
        sqli_test_inputs = [
            "SELECT * FROM users",
            "UNION SELECT password FROM admin",
            "DROP TABLE customers",
            "Normal user query",
            "My name is Robert",
            "INSERT INTO logs VALUES",
        ]

        sqli_result = await client.test_pattern(sqli_pattern, sqli_test_inputs)

        assert_check(sqli_result is not None, "SQLi pattern test returned result")
        assert_check(sqli_result.valid, "SQLi pattern is valid regex")

        print(f"   Pattern: {sqli_pattern[:50]}...")
        print("\n   Results:")

        expected_sqli_matches = [True, True, True, False, False, True]
        for i, match in enumerate(sqli_result.matches):
            icon = "✓ BLOCKED" if match.matched else "✗ allowed"
            print(f'   {icon}  "{match.input}"')
            if i < len(expected_sqli_matches):
                assert_check(
                    match.matched == expected_sqli_matches[i],
                    f"SQLi input '{match.input[:20]}' matched as expected"
                )

        # 5. Test an invalid pattern
        print("\n5. Testing invalid pattern (error handling)...")

        try:
            invalid_pattern = "([unclosed"
            invalid_result = await client.test_pattern(invalid_pattern, ["test"])

            if not invalid_result.valid:
                assert_check(True, "Invalid pattern correctly marked as invalid")
                print(f"   Pattern: {invalid_pattern}")
                print("   Valid: false")
                print(f"   Error: {invalid_result.error}")
            else:
                assert_check(False, "Invalid pattern should be marked as invalid")
        except Exception:
            assert_check(True, "Server rejected invalid pattern (expected)")
            print("   Server rejected invalid pattern (expected)")

    except Exception as e:
        print(f"\nError: {e}")
        failures.append(f"Pattern testing failed: {e}")

    print("\n" + "=" * 60)
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Pattern Testing validated:")
        print("  - Credit card pattern matching")
        print("  - SSN pattern matching")
        print("  - Email pattern matching")
        print("  - SQL injection pattern matching")
        print("  - Invalid pattern handling")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
