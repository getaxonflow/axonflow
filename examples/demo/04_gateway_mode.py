"""
Gateway Mode - Keep Your Existing LLM Calls

Use ANY LLM client (OpenAI SDK, LangChain, CrewAI, LiteLLM, etc.) with AxonFlow.
This example uses LangChain. The same pattern works with any framework.

Flow: Pre-check -> Your LLM Call -> Audit
"""

import asyncio
import os
import time

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage

from axonflow import AxonFlow
from axonflow.types import TokenUsage

async def main():
    # Initialize LangChain LLM (your API key, your control)
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.7,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as ax:
        query = "Explain AI governance in one sentence"

        # Step 1: Pre-check (policy evaluation)
        print("Step 1: Policy Pre-Check")
        print("-" * 40)
        ctx = await ax.get_policy_approved_context(
            user_token="demo-user",
            query=query,
        )

        print(f"Context ID: {ctx.context_id}")
        print(f"Approved: {ctx.approved}")
        print(f"Policies: {ctx.policies}")

        if not ctx.approved:
            print(f"Blocked: {ctx.block_reason}")
            return

        # Step 2: Your LangChain LLM call
        print("\nStep 2: LLM Call (LangChain)")
        print("-" * 40)
        start = time.time()
        response = llm.invoke([HumanMessage(content=query)])
        latency_ms = int((time.time() - start) * 1000)

        content = response.content
        usage = response.usage_metadata or {}

        print(f"Response: {content}")
        print(f"Latency: {latency_ms}ms")

        # Step 3: Audit the call
        print("\nStep 3: Audit Record")
        print("-" * 40)
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)

        audit_result = await ax.audit_llm_call(
            context_id=ctx.context_id,
            response_summary=content[:100],
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            latency_ms=latency_ms,
        )
        print(f"Audit ID: {audit_result.audit_id}")
        print(f"Token Usage: {prompt_tokens + completion_tokens} tokens")
        print(f"  - Prompt: {prompt_tokens}")
        print(f"  - Completion: {completion_tokens}")

if __name__ == "__main__":
    asyncio.run(main())
