"""
AxonFlow + LangChain Integration

Use ANY LangChain LLM (OpenAI, Anthropic, Ollama, etc.) with AxonFlow governance.
This example shows the Gateway Mode pattern with LangChain:

1. Pre-check: Validate request against policies
2. LangChain Call: Your existing LangChain code
3. Audit: Log the interaction for compliance

This preserves your LangChain workflow while adding governance.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


async def main():
    print("AxonFlow + LangChain Integration Example")
    print()

    # Initialize LangChain LLM (your API key, your control)
    llm = ChatOpenAI(
        model="gpt-4",
        temperature=0.7,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:
        query = "What are the key principles of responsible AI development?"
        user_token = "user-langchain-demo"
        context = {
            "user_role": "developer",
            "framework": "langchain",
        }

        print(f'Query: "{query}"')
        print(f"User: {user_token}")
        print()

        # =====================================================================
        # STEP 1: Pre-Check (Policy Evaluation)
        # =====================================================================
        print("Step 1: Policy Pre-Check")
        print("-" * 40)

        pre_check_start = time.time()
        ctx = await axonflow.get_policy_approved_context(
            user_token=user_token,
            query=query,
            context=context,
        )
        pre_check_latency_ms = int((time.time() - pre_check_start) * 1000)

        print(f"Context ID: {ctx.context_id}")
        print(f"Approved: {ctx.approved}")
        print(f"Policies: {ctx.policies}")
        print(f"Latency: {pre_check_latency_ms}ms")

        if not ctx.approved:
            print(f"Blocked: {ctx.block_reason}")
            return

        # =====================================================================
        # STEP 2: Your LangChain LLM Call
        # =====================================================================
        print()
        print("Step 2: LangChain LLM Call")
        print("-" * 40)

        llm_start = time.time()

        # Standard LangChain call - no modifications needed
        response = llm.invoke([
            SystemMessage(content="You are an AI ethics expert. Be concise and practical."),
            HumanMessage(content=query),
        ])

        llm_latency_ms = int((time.time() - llm_start) * 1000)

        content = response.content
        usage = response.usage_metadata or {}

        print(f"Response length: {len(content)} chars")
        print(f"Latency: {llm_latency_ms}ms")

        # =====================================================================
        # STEP 3: Audit the Call
        # =====================================================================
        print()
        print("Step 3: Audit Record")
        print("-" * 40)

        # Extract token usage from LangChain response
        prompt_tokens = usage.get("input_tokens", 0)
        completion_tokens = usage.get("output_tokens", 0)

        audit_start = time.time()
        audit_result = await axonflow.audit_llm_call(
            context_id=ctx.context_id,
            response_summary=content[:100],
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            latency_ms=llm_latency_ms,
        )
        audit_latency_ms = int((time.time() - audit_start) * 1000)

        print(f"Audit ID: {audit_result.audit_id}")
        print(f"Token Usage: {prompt_tokens + completion_tokens} tokens")
        print(f"  - Prompt: {prompt_tokens}")
        print(f"  - Completion: {completion_tokens}")
        print(f"Audit Latency: {audit_latency_ms}ms")

        # =====================================================================
        # Results Summary
        # =====================================================================
        print()
        print("=" * 60)
        print("RESPONSE")
        print("=" * 60)
        print(content)
        print()
        governance_overhead = pre_check_latency_ms + audit_latency_ms
        print(f"Governance overhead: {governance_overhead}ms")
        print(f"  (Pre-check: {pre_check_latency_ms}ms + Audit: {audit_latency_ms}ms)")


if __name__ == "__main__":
    asyncio.run(main())
