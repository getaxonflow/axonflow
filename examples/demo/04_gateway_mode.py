"""
Gateway Mode - Keep Your Existing LLM Calls

Already using LangChain or CrewAI? Keep your existing LLM calls.
AxonFlow adds governance around them. No rewrite required.
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
        ctx = await ax.get_policy_approved_context(
            user_token="demo-user",
            query="What's the weather in London?",
        )

        if not ctx.approved:
            print(f"Blocked: {ctx.block_reason}")
            return

        # Step 2: Your existing LLM call (your API key, your control)
        start = time.time()
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "What's the weather in London?"}]
        )
        latency_ms = int((time.time() - start) * 1000)

        # Step 3: Audit the call
        await ax.audit_llm_call(
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

        print(response.choices[0].message.content)

if __name__ == "__main__":
    asyncio.run(main())
