#!/usr/bin/env python3
"""
AxonFlow LLM Interceptor Example - Python

Demonstrates how to wrap LLM provider clients with AxonFlow governance
using interceptors. This provides transparent policy enforcement without
changing your existing LLM call patterns.

This example uses Community Mode (self-hosted) which doesn't require
authentication credentials. For enterprise deployments, you can add
client_id and client_secret parameters.

Interceptors automatically:
- Pre-check queries against policies before LLM calls
- Block requests that violate policies
- Audit LLM responses for compliance tracking

Requirements:
    pip install axonflow>=0.11.0 openai

Usage:
    export AXONFLOW_AGENT_URL=http://localhost:8080
    export OPENAI_API_KEY=your-openai-key
    python main.py
"""

import os

from openai import OpenAI

from axonflow import AxonFlow
from axonflow.interceptors.openai import wrap_openai_client
from axonflow.exceptions import PolicyViolationError


def main():
    print("AxonFlow LLM Interceptor Example - Python")
    print("=" * 60)
    print()

    # Initialize AxonFlow client in Community Mode (no authentication required)
    # For enterprise deployments, add: client_id="...", client_secret="..."
    axonflow = AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
    )

    # Initialize OpenAI client
    openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    # Wrap OpenAI client with AxonFlow governance
    # All calls through this client will be policy-checked automatically
    governed_client = wrap_openai_client(
        openai_client,
        axonflow,
        user_token="user-123"
    )

    print("Testing LLM Interceptor with OpenAI")
    print("-" * 60)
    print()

    # Example 1: Safe query (should pass)
    print("Example 1: Safe Query")
    print("-" * 40)
    try:
        response = governed_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "What is the capital of France?"}
            ],
            max_tokens=100
        )
        print(f"Query: What is the capital of France?")
        print(f"Status: APPROVED")
        print(f"Response: {response.choices[0].message.content}")
    except PolicyViolationError as e:
        print(f"Status: BLOCKED")
        print(f"Reason: {e}")
    except Exception as e:
        print(f"Error: {e}")

    print()

    # Example 2: Query with PII (should be blocked by default policies)
    print("Example 2: Query with PII (Expected: Blocked)")
    print("-" * 40)
    try:
        response = governed_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "Process refund for SSN 123-45-6789"}
            ],
            max_tokens=100
        )
        print(f"Query: Process refund for SSN 123-45-6789")
        print(f"Status: APPROVED")
        print(f"Response: {response.choices[0].message.content}")
    except PolicyViolationError as e:
        print(f"Query: Process refund for SSN 123-45-6789")
        print(f"Status: BLOCKED")
        print(f"Reason: {e}")
    except Exception as e:
        print(f"Error: {e}")

    print()

    # Example 3: SQL injection attempt (should be blocked)
    print("Example 3: SQL Injection (Expected: Blocked)")
    print("-" * 40)
    try:
        response = governed_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": "SELECT * FROM users WHERE 1=1; DROP TABLE users;--"}
            ],
            max_tokens=100
        )
        print(f"Query: SELECT * FROM users WHERE 1=1; DROP TABLE users;--")
        print(f"Status: APPROVED")
        print(f"Response: {response.choices[0].message.content}")
    except PolicyViolationError as e:
        print(f"Query: SELECT * FROM users WHERE 1=1; DROP TABLE users;--")
        print(f"Status: BLOCKED")
        print(f"Reason: {e}")
    except Exception as e:
        print(f"Error: {e}")

    print()
    print("=" * 60)
    print("Python LLM Interceptor Test: COMPLETE")


if __name__ == "__main__":
    main()
