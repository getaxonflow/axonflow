"""
AxonFlow Policy Management - Test Pattern

This example demonstrates how to test regex patterns
before creating policies. This helps ensure your patterns
work correctly and catch the right inputs.
"""

import asyncio
import os

from axonflow import AxonFlow


async def main() -> None:
    """Test various regex patterns."""
    client = AxonFlow(
        agent_url=os.getenv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
        client_id="test-org-001",  # Used as tenant ID
        client_secret="test-secret",  # Not validated in Community mode
    )

    print("AxonFlow Policy Management - Pattern Testing")
    print("=" * 60)

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

        print(f"   Pattern: {cc_pattern}")
        print(f"   Valid regex: {cc_result.valid}")
        print("\n   Results:")

        for match in cc_result.matches:
            icon = "\u2713 MATCH" if match.matched else "\u2717 no match"
            print(f'   {icon}  "{match.input}"')

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

        print(f"   Pattern: {ssn_pattern}")
        print("\n   Results:")

        for match in ssn_result.matches:
            icon = "\u2713 MATCH" if match.matched else "\u2717 no match"
            print(f'   {icon}  "{match.input}"')

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

        print(f"   Pattern: {email_pattern}")
        print("\n   Results:")

        for match in email_result.matches:
            icon = "\u2713 MATCH" if match.matched else "\u2717 no match"
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

        print(f"   Pattern: {sqli_pattern[:50]}...")
        print("\n   Results:")

        for match in sqli_result.matches:
            icon = "\u2713 BLOCKED" if match.matched else "\u2717 allowed"
            print(f'   {icon}  "{match.input}"')

        # 5. Test an invalid pattern
        print("\n5. Testing invalid pattern (error handling)...")

        try:
            invalid_pattern = "([unclosed"
            invalid_result = await client.test_pattern(invalid_pattern, ["test"])

            if not invalid_result.valid:
                print(f"   Pattern: {invalid_pattern}")
                print("   Valid: false")
                print(f"   Error: {invalid_result.error}")
        except Exception:
            print("   Server rejected invalid pattern (expected)")

        # Summary
        print("\n" + "=" * 60)
        print("Pattern Testing Summary")
        print("=" * 60)
        print(
            """
Best Practices:
  1. Always test patterns before creating policies
  2. Include edge cases in your test inputs
  3. Test with real-world examples from your domain
  4. Consider case sensitivity (use (?i) for case-insensitive)
  5. Use word boundaries (\\b) to avoid partial matches
"""
        )

    except Exception as e:
        print(f"\nError: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
