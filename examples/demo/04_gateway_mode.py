"""
Gateway Mode - Keep Your Existing LLM Calls

Use ANY LLM client (OpenAI SDK, LangChain, CrewAI, LiteLLM, etc.) with AxonFlow.
This example uses direct OpenAI SDK. The same pattern works with any framework.

Flow: Pre-check -> Your LLM Call -> Audit
"""

import asyncio
import os
import time

import openai
from axonflow import AxonFlow
from axonflow.types import TokenUsage

async def main():
    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:
        # Step 1: Pre-check (policy evaluation)
        print("Step 1: Policy Pre-Check")
        print("-" * 40)
        ctx = await ax.get_policy_approved_context(
            user_token="demo-user",
            query="Explain AI governance in one sentence",
        )

        print(f"Context ID: {ctx.context_id}")
        print(f"Approved: {ctx.approved}")
        print(f"Policies: {ctx.policies}")

        if not ctx.approved:
            print(f"Blocked: {ctx.block_reason}")
            return

        # Step 2: Your existing LLM call (your API key, your control)
        print("\nStep 2: LLM Call (Direct OpenAI SDK)")
        print("-" * 40)
        start = time.time()
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Explain AI governance in one sentence"}]
        )
        latency_ms = int((time.time() - start) * 1000)
        print(f"Response: {response.choices[0].message.content}")
        print(f"Latency: {latency_ms}ms")

        # Step 3: Audit the call
        print("\nStep 3: Audit Record")
        print("-" * 40)
        audit_result = await ax.audit_llm_call(
            context_id=ctx.context_id,
            response_summary=response.choices[0].message.content[:100],
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=response.usage.prompt_tokens,
                completion_tokens=response.usage.completion_tokens,
                total_tokens=response.usage.total_tokens,
            ),
            latency_ms=latency_ms,
        )
        print(f"Audit ID: {audit_result.audit_id}")
        print(f"Token Usage: {response.usage.total_tokens} tokens")
        print(f"  - Prompt: {response.usage.prompt_tokens}")
        print(f"  - Completion: {response.usage.completion_tokens}")

if __name__ == "__main__":
    asyncio.run(main())
