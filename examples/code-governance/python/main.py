"""
AxonFlow Code Governance - Python

Demonstrates code artifact detection in LLM responses:
1. Send a code generation query to AxonFlow
2. AxonFlow automatically detects code in the response
3. Code metadata is included in policy_info for audit

The code_artifact field contains:
- language: Detected programming language
- code_type: Category (function, class, script, config, snippet)
- size_bytes: Size of detected code
- line_count: Number of lines
- secrets_detected: Count of potential secrets
- unsafe_patterns: Count of unsafe code patterns

Prerequisites:
- AxonFlow Agent running on localhost:8080
- OpenAI or Anthropic API key configured in AxonFlow

Usage:
    cp .env.example .env  # Configure your settings
    pip install -r requirements.txt
    python main.py
"""

import asyncio
import os

from axonflow import AxonFlow


async def main():
    print("AxonFlow Code Governance - Python")
    print("=" * 60)
    print()
    print("This demo shows automatic code detection in LLM responses.")
    print()

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:

        # Example 1: Generate a safe function
        print("-" * 60)
        print("Example 1: Generate a Python function")
        print("-" * 60)

        response = await ax.execute_query(
            user_token="developer-123",
            query="Write a Python function to validate email addresses using regex",
            request_type="chat",
        )

        if response.blocked:
            print(f"Status: BLOCKED - {response.block_reason}")
        else:
            print("Status: ALLOWED")
            print()

            # Display the LLM response
            data = response.data.get("data") if isinstance(response.data, dict) else response.data
            data_str = str(data)
            print("Response preview:")
            print(f"  {data_str[:300]}..." if len(data_str) > 300 else f"  {data_str}")
            print()

            # Display audit trail
            print("Audit Trail:")
            if response.policy_info:
                print(f"  Processing Time: {response.policy_info.processing_time}")
                print(f"  Static Checks: {response.policy_info.static_checks}")

                # Code Governance: Check for code artifact metadata
                # This is populated when the LLM response contains code
                if response.policy_info.code_artifact:
                    artifact = response.policy_info.code_artifact
                    print()
                    print("Code Artifact Detected:")
                    print(f"  Language: {artifact.language}")
                    print(f"  Type: {artifact.code_type}")
                    print(f"  Size: {artifact.size_bytes} bytes")
                    print(f"  Lines: {artifact.line_count}")
                    print(f"  Secrets Detected: {artifact.secrets_detected}")
                    print(f"  Unsafe Patterns: {artifact.unsafe_patterns}")

        print()

        # Example 2: Request code - check for unsafe patterns
        print("-" * 60)
        print("Example 2: Check for unsafe patterns in generated code")
        print("-" * 60)

        response = await ax.execute_query(
            user_token="developer-123",
            query="Write a Python script that reads user input and uses subprocess to run it as a shell command",
            request_type="chat",
        )

        if response.blocked:
            print(f"Status: BLOCKED - {response.block_reason}")
        else:
            print("Status: ALLOWED")
            print()

            if response.policy_info:
                print(f"Processing Time: {response.policy_info.processing_time}")

                if response.policy_info.code_artifact:
                    artifact = response.policy_info.code_artifact
                    print()
                    print("Code Artifact Analysis:")
                    print(f"  Language: {artifact.language}")
                    print(f"  Unsafe Patterns: {artifact.unsafe_patterns}")

                    if artifact.unsafe_patterns > 0:
                        print()
                        print(f"  WARNING: {artifact.unsafe_patterns} unsafe code pattern(s) detected!")
                        print("  Detected patterns may include: subprocess, shell execution")
                        print("  Review carefully before using in production.")

        print()
        print("=" * 60)
        print("Summary")
        print("=" * 60)
        print()
        print("Code Governance automatically:")
        print("  1. Detects code blocks in LLM responses")
        print("  2. Identifies the programming language")
        print("  3. Counts potential secrets and unsafe patterns")
        print("  4. Includes metadata in policy_info for audit")
        print()
        print("Use this metadata to:")
        print("  - Alert on unsafe patterns before deployment")
        print("  - Track code generation for compliance")
        print("  - Build dashboards for AI code generation metrics")
        print()


if __name__ == "__main__":
    asyncio.run(main())
