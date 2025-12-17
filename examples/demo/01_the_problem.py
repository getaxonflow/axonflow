"""
Part 1: The Problem - Unprotected AI

This demonstrates the risks of calling LLMs without governance:
- No audit trail
- No PII protection
- No injection prevention
- No cost controls

Run this to see what most AI applications do today - and why it's risky.
"""

import os
import time

# Try to import OpenAI, but gracefully handle if not installed
try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


def simulate_unprotected_call():
    """Simulate what happens without governance."""
    print("Unprotected LLM Call")
    print("=" * 50)
    print()

    # Dangerous query with PII
    query = "Process refund for customer. Card: 4111-1111-1111-1111, SSN: 123-45-6789"

    print(f"Query: \"{query}\"")
    print()

    # Simulate sending directly to LLM
    print("Sending directly to LLM...")
    time.sleep(0.5)
    print()

    # Show what happens (simulated)
    print("Result:")
    print("-" * 50)
    print("  Response: 'I'll help process the refund for the")
    print("             card ending in 1111...'")
    print()
    print("What just happened:")
    print("-" * 50)
    print("  [!] PII sent to external LLM (credit card, SSN)")
    print("  [!] No audit record created")
    print("  [!] No policy enforcement")
    print("  [!] No rate limiting")
    print("  [!] Full prompt visible in LLM provider logs")
    print()


def real_unprotected_call():
    """Actually call OpenAI without any governance (if API key available)."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[Skipping real OpenAI call - no API key configured]")
        print()
        return

    client = OpenAI(api_key=api_key)

    print("Making real unprotected call to OpenAI...")
    print()

    # A simple query (we won't actually send PII to demonstrate)
    query = "What are the key benefits of AI governance?"

    start = time.time()
    response = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": query}],
        max_tokens=100,
    )
    latency = int((time.time() - start) * 1000)

    print(f"Query: \"{query}\"")
    print(f"Latency: {latency}ms")
    print()
    print("Response:")
    print("-" * 50)
    content = response.choices[0].message.content
    print(f"  {content[:200]}...")
    print()
    print("Missing:")
    print("-" * 50)
    print("  - No audit log")
    print("  - No policy checks")
    print("  - No PII scanning")
    print("  - No usage tracking")
    print()


def main():
    simulate_unprotected_call()

    if HAS_OPENAI:
        real_unprotected_call()
    else:
        print("[OpenAI SDK not installed - simulation only]")
        print("Install with: pip install openai")


if __name__ == "__main__":
    main()
