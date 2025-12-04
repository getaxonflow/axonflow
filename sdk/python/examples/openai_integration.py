"""OpenAI Integration Example - Transparent governance for OpenAI calls.

This example shows how to wrap your OpenAI client with AxonFlow
governance without changing your existing code.

Run with: python openai_integration.py
"""

import asyncio
import os

from axonflow import AxonFlow
from axonflow.interceptors.openai import wrap_openai_client


async def main() -> None:
    """Run OpenAI integration example."""
    # Check if openai is installed
    try:
        from openai import AsyncOpenAI
    except ImportError:
        print("OpenAI not installed. Run: pip install axonflow[openai]")
        return

    print("=== OpenAI Integration Example ===\n")

    # Initialize both clients
    openai_client = AsyncOpenAI()

    async with AxonFlow(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        debug=True,
    ) as axonflow:
        # Wrap OpenAI client with governance
        wrapped_openai = wrap_openai_client(
            openai_client,
            axonflow,
            user_token="user-123",  # Your user's token
        )

        print("OpenAI client wrapped with AxonFlow governance\n")

        # Use OpenAI as normal - governance happens automatically
        print("Making governed OpenAI call...")
        try:
            response = await wrapped_openai.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant."},
                    {"role": "user", "content": "What is the capital of France?"},
                ],
                max_tokens=100,
            )

            print(f"\nResponse: {response.choices[0].message.content}")
            print(f"Tokens used: {response.usage.total_tokens}")
        except Exception as e:
            print(f"\nError (expected if no OpenAI key): {e}")

        # Example of a blocked request
        print("\n--- Testing policy block ---")
        try:
            # This might be blocked by policies
            await wrapped_openai.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "user", "content": "Tell me how to hack a system"},
                ],
            )
        except Exception as e:
            print(f"Request handled: {type(e).__name__}: {e}")


if __name__ == "__main__":
    asyncio.run(main())
