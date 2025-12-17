"""
AxonFlow Gateway Mode - OpenAI Example

Gateway Mode provides the lowest latency AI governance by separating
policy enforcement from LLM calls. The workflow is:

1. Pre-check: Validate request against policies BEFORE calling LLM
2. LLM Call: Make your own call to your preferred provider
3. Audit: Log the interaction for compliance and monitoring

This gives you full control over LLM parameters while maintaining
complete audit trails with ~3-5ms governance overhead.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from openai import OpenAI
from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


async def main():
    print("AxonFlow Gateway Mode - Python Example")
    print()

    # Initialize clients
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:
        openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # Example request
        user_token = "user-123"
        query = "What are best practices for AI model deployment?"
        context = {
            "user_role": "engineer",
            "department": "platform",
        }

        print(f'Query: "{query}"')
        print(f"User: {user_token}")
        print(f"Context: {context}")
        print()

        # =====================================================================
        # STEP 1: Pre-Check - Validate against policies before LLM call
        # =====================================================================
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
        print(f"   Approved: {pre_check_result.approved}")

        if not pre_check_result.approved:
            print(f"   Blocked: {pre_check_result.block_reason}")
            print(f"   Policies: {pre_check_result.policies}")
            return

        print()

        # =====================================================================
        # STEP 2: LLM Call - Make your own call to OpenAI
        # =====================================================================
        print("Step 2: LLM Call (OpenAI)...")
        llm_start = time.time()

        completion = openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful AI expert. Be concise.",
                },
                {
                    "role": "user",
                    "content": query,
                },
            ],
            max_tokens=200,
        )

        llm_latency_ms = int((time.time() - llm_start) * 1000)
        response = completion.choices[0].message.content
        usage = completion.usage

        print(f"   Response received in {llm_latency_ms}ms")
        print(f"   Tokens: {usage.prompt_tokens} prompt, {usage.completion_tokens} completion")
        print()

        # =====================================================================
        # STEP 3: Audit - Log the interaction for compliance
        # =====================================================================
        print("Step 3: Audit Logging...")
        audit_start = time.time()

        audit_result = await axonflow.audit_llm_call(
            context_id=pre_check_result.context_id,
            response_summary=response[:100] if len(response) > 100 else response,
            provider="openai",
            model="gpt-3.5-turbo",
            token_usage=TokenUsage(
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
                total_tokens=usage.total_tokens,
            ),
            latency_ms=llm_latency_ms,
        )

        audit_latency_ms = int((time.time() - audit_start) * 1000)
        print(f"   Audit logged in {audit_latency_ms}ms")
        print(f"   Audit ID: {audit_result.audit_id}")
        print()

        # =====================================================================
        # Results
        # =====================================================================
        governance_overhead_ms = pre_check_latency_ms + audit_latency_ms
        total_latency_ms = pre_check_latency_ms + llm_latency_ms + audit_latency_ms

        print("=" * 60)
        print("Results")
        print("=" * 60)
        print(f"\nResponse:\n{response}\n")
        print("Latency Breakdown:")
        print(f"   Pre-check:  {pre_check_latency_ms}ms")
        print(f"   LLM call:   {llm_latency_ms}ms")
        print(f"   Audit:      {audit_latency_ms}ms")
        print("   " + "-" * 17)
        print(f"   Governance: {governance_overhead_ms}ms (overhead)")
        print(f"   Total:      {total_latency_ms}ms")


if __name__ == "__main__":
    asyncio.run(main())
