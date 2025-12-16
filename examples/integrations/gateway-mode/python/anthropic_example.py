"""
AxonFlow Gateway Mode - Anthropic Claude Example

Demonstrates Gateway Mode with Anthropic's Claude models.
Same pattern as OpenAI: Pre-check -> LLM Call -> Audit
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from anthropic import Anthropic
from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


async def main():
    print("AxonFlow Gateway Mode - Anthropic Claude Example")
    print()

    # Initialize clients
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:
        anthropic = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        # Example request
        user_token = "user-456"
        query = "Explain the importance of audit trails in AI systems."
        context = {
            "user_role": "compliance_officer",
            "department": "legal",
        }

        print(f'Query: "{query}"')
        print(f"User: {user_token}")
        print()

        # Step 1: Pre-Check
        print("Step 1: Policy Pre-Check...")
        pre_check_start = time.time()

        pre_check_result = await axonflow.get_policy_approved_context(
            user_token=user_token,
            query=query,
            context=context,
        )

        pre_check_latency_ms = int((time.time() - pre_check_start) * 1000)
        print(f"   Completed in {pre_check_latency_ms}ms")
        print(f"   Context ID: {pre_check_result.context_id}")

        if not pre_check_result.approved:
            print(f"   Blocked: {pre_check_result.block_reason}")
            return

        print()

        # Step 2: Claude LLM Call
        print("Step 2: LLM Call (Claude)...")
        llm_start = time.time()

        message = anthropic.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=200,
            messages=[
                {
                    "role": "user",
                    "content": query,
                },
            ],
        )

        llm_latency_ms = int((time.time() - llm_start) * 1000)
        response = message.content[0].text if message.content else ""

        print(f"   Response received in {llm_latency_ms}ms")
        print(f"   Tokens: {message.usage.input_tokens} in, {message.usage.output_tokens} out")
        print()

        # Step 3: Audit
        print("Step 3: Audit Logging...")
        audit_start = time.time()

        await axonflow.audit_llm_call(
            context_id=pre_check_result.context_id,
            response_summary=response[:100] if len(response) > 100 else response,
            provider="anthropic",
            model="claude-3-haiku-20240307",
            token_usage=TokenUsage(
                prompt_tokens=message.usage.input_tokens,
                completion_tokens=message.usage.output_tokens,
                total_tokens=message.usage.input_tokens + message.usage.output_tokens,
            ),
            latency_ms=llm_latency_ms,
        )

        audit_latency_ms = int((time.time() - audit_start) * 1000)
        print(f"   Audit logged in {audit_latency_ms}ms")
        print()

        # Results
        governance_overhead_ms = pre_check_latency_ms + audit_latency_ms
        print("=" * 60)
        print(f"Response:\n{response}\n")
        print(f"Governance overhead: {governance_overhead_ms}ms")
        print(f"   (Pre-check: {pre_check_latency_ms}ms + Audit: {audit_latency_ms}ms)")


if __name__ == "__main__":
    asyncio.run(main())
