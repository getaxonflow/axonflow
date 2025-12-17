"""
Part 3.2: Gateway Mode Integration

Gateway Mode gives you lowest latency and full control:
  Step 1: Pre-check (is this query allowed?)
  Step 2: Your LLM call (you control the provider)
  Step 3: Audit (log what happened)

Typical overhead: <5ms per step.
Use this when you need to keep your existing LLM integration.
"""

import asyncio
import os
import time

from axonflow import AxonFlow
from axonflow.types import TokenUsage


# Try to import OpenAI for the demo
try:
    from openai import OpenAI
    HAS_OPENAI = bool(os.getenv("OPENAI_API_KEY"))
except ImportError:
    HAS_OPENAI = False


async def gateway_mode_demo():
    print("Gateway Mode Demo")
    print("=" * 60)
    print()
    print("Flow: Pre-check → Your LLM Call → Audit")
    print("      (You control the LLM, AxonFlow governs)")
    print()

    agent_url = os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")

    async with AxonFlow(
        agent_url=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as client:

        query = "Summarize the key points for handling escalated tickets"

        # Step 1: Pre-check
        print("-" * 60)
        print("Step 1: Pre-check (Policy Evaluation)")
        print("-" * 60)

        precheck_start = time.time()
        ctx = await client.get_policy_approved_context(
            user_token="support-agent-demo",
            query=query,
        )
        precheck_ms = int((time.time() - precheck_start) * 1000)

        print(f"Query: \"{query}\"")
        print()
        print(f"Approved: {ctx.approved}")
        print(f"Context ID: {ctx.context_id}")
        print(f"Pre-check Latency: {precheck_ms}ms")

        if not ctx.approved:
            print(f"Blocked: {ctx.block_reason}")
            return

        if ctx.policies:
            print(f"Policies Checked: {ctx.policies}")

        print()

        # Step 2: Your LLM Call
        print("-" * 60)
        print("Step 2: Your LLM Call")
        print("-" * 60)

        llm_response = ""
        prompt_tokens = 0
        completion_tokens = 0
        llm_latency = 0

        if HAS_OPENAI:
            print("Calling OpenAI (your API key, your control)...")
            print()

            openai_client = OpenAI()
            llm_start = time.time()

            response = openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful support assistant."},
                    {"role": "user", "content": query},
                ],
                max_tokens=150,
            )

            llm_latency = int((time.time() - llm_start) * 1000)
            llm_response = response.choices[0].message.content
            prompt_tokens = response.usage.prompt_tokens if response.usage else 0
            completion_tokens = response.usage.completion_tokens if response.usage else 0

            print(f"Response: {llm_response[:150]}...")
            print(f"LLM Latency: {llm_latency}ms")
            print(f"Tokens: {prompt_tokens} prompt + {completion_tokens} completion")
        else:
            print("[OpenAI not configured - simulating LLM response]")
            print()
            llm_response = "For escalated tickets: 1) Acknowledge urgency, 2) Gather context, 3) Escalate to tier 2 if needed."
            prompt_tokens = 25
            completion_tokens = 30
            llm_latency = 450  # Simulated
            print(f"Response: {llm_response}")
            print(f"[Simulated] Latency: {llm_latency}ms")

        print()

        # Step 3: Audit
        print("-" * 60)
        print("Step 3: Audit Record")
        print("-" * 60)

        audit_start = time.time()
        audit_result = await client.audit_llm_call(
            context_id=ctx.context_id,
            response_summary=llm_response[:100],
            provider="openai" if HAS_OPENAI else "simulated",
            model="gpt-3.5-turbo",
            token_usage=TokenUsage(
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
            ),
            latency_ms=llm_latency,
        )
        audit_ms = int((time.time() - audit_start) * 1000)

        print(f"Audit ID: {audit_result.audit_id}")
        print(f"Audit Latency: {audit_ms}ms")

        print()

        # Summary
        total_overhead = precheck_ms + audit_ms
        print("=" * 60)
        print("Gateway Mode Summary")
        print("=" * 60)
        print()
        print(f"Pre-check:     {precheck_ms}ms")
        print(f"Your LLM call: {llm_latency}ms")
        print(f"Audit:         {audit_ms}ms")
        print(f"───────────────────────")
        print(f"AxonFlow overhead: {total_overhead}ms (pre-check + audit)")
        print()
        print("Benefits:")
        print("  - Keep your existing LLM integration")
        print("  - Minimal latency overhead (<10ms typical)")
        print("  - Full audit trail with token tracking")
        print("  - Policy enforcement before LLM call")
        print()


if __name__ == "__main__":
    asyncio.run(gateway_mode_demo())
