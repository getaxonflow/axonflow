"""Gateway Mode Example - Direct LLM calls with AxonFlow governance.

This example shows how to use Gateway Mode for lowest-latency LLM calls
while maintaining full governance and audit compliance.

Gateway Mode Flow:
1. Pre-check: Get policy approval and filtered data
2. LLM Call: Make direct call to your LLM provider
3. Audit: Report the call for compliance

Run with: python gateway_mode.py
"""

import asyncio
import os
import time

from axonflow import AxonFlow, TokenUsage

# Simulated LLM response (replace with actual OpenAI/Anthropic call)
MOCK_LLM_RESPONSE = {
    "choices": [
        {
            "message": {
                "content": "Found 5 patients with recent lab results: P001, P002, P003, P004, P005"
            }
        }
    ],
    "usage": {
        "prompt_tokens": 150,
        "completion_tokens": 45,
        "total_tokens": 195,
    },
}


async def main() -> None:
    """Run Gateway Mode example."""
    async with AxonFlow(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        license_key=os.environ.get("AXONFLOW_LICENSE_KEY"),
        debug=True,
    ) as axonflow:
        print("=== Gateway Mode Example ===\n")

        # =====================================================================
        # Step 1: Pre-check - Get policy approval before LLM call
        # =====================================================================
        print("Step 1: Policy Pre-Check")
        print("-" * 40)

        ctx = await axonflow.get_policy_approved_context(
            user_token="user-jwt-token",  # Your user's JWT
            query="Find patients with recent lab results",
            data_sources=["postgres"],  # MCP connectors to fetch data from
            context={"department": "cardiology"},  # Additional context
        )

        print(f"  Context ID: {ctx.context_id}")
        print(f"  Approved: {ctx.approved}")
        print(f"  Policies: {ctx.policies}")
        print(f"  Expires: {ctx.expires_at}")

        if ctx.rate_limit_info:
            print(f"  Rate Limit: {ctx.rate_limit_info.remaining}/{ctx.rate_limit_info.limit}")

        if not ctx.approved:
            print(f"\n❌ Request blocked: {ctx.block_reason}")
            return

        print(f"  Approved Data Keys: {list(ctx.approved_data.keys())}")
        print("\n✅ Pre-check passed!\n")

        # =====================================================================
        # Step 2: Make LLM call directly (lowest latency)
        # =====================================================================
        print("Step 2: Direct LLM Call")
        print("-" * 40)

        # Build prompt using approved data (filtered by policies)
        prompt = f"""Based on this data: {ctx.approved_data}

Please summarize the patient results."""

        print(f"  Prompt length: {len(prompt)} chars")

        # Time the LLM call
        start_time = time.time()

        # In production, this would be:
        # response = await openai.chat.completions.create(
        #     model="gpt-4",
        #     messages=[
        #         {"role": "system", "content": "You are a helpful healthcare assistant."},
        #         {"role": "user", "content": prompt},
        #     ],
        # )

        # Simulated response for demo
        llm_response = MOCK_LLM_RESPONSE
        await asyncio.sleep(0.1)  # Simulate latency

        latency_ms = int((time.time() - start_time) * 1000)
        content = llm_response["choices"][0]["message"]["content"]

        print(f"  Latency: {latency_ms}ms")
        print(f"  Response: {content[:100]}...")
        print(f"  Tokens: {llm_response['usage']['total_tokens']}")
        print("\n✅ LLM call complete!\n")

        # =====================================================================
        # Step 3: Audit the call for compliance
        # =====================================================================
        print("Step 3: Audit Logging")
        print("-" * 40)

        audit_result = await axonflow.audit_llm_call(
            context_id=ctx.context_id,  # Links to pre-check
            response_summary=content[:100],  # Brief summary, not full response
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=llm_response["usage"]["prompt_tokens"],
                completion_tokens=llm_response["usage"]["completion_tokens"],
                total_tokens=llm_response["usage"]["total_tokens"],
            ),
            latency_ms=latency_ms,
            metadata={
                "department": "cardiology",
                "session_id": "session-123",
            },
        )

        print(f"  Audit ID: {audit_result.audit_id}")
        print(f"  Success: {audit_result.success}")
        print("\n✅ Audit recorded!\n")

        print("=" * 40)
        print("Gateway Mode flow complete!")
        print("=" * 40)


async def blocked_example() -> None:
    """Example showing a blocked request."""
    async with AxonFlow(
        agent_url=os.environ.get("AXONFLOW_AGENT_URL", "https://staging-eu.getaxonflow.com"),
        client_id=os.environ.get("AXONFLOW_CLIENT_ID", "demo-client"),
        client_secret=os.environ.get("AXONFLOW_CLIENT_SECRET", "demo-secret"),
        debug=True,
    ) as axonflow:
        print("\n=== Blocked Request Example ===\n")

        ctx = await axonflow.get_policy_approved_context(
            user_token="user-jwt-token",
            query="Show me all social security numbers",  # Sensitive query
        )

        if not ctx.approved:
            print(f"❌ Request blocked!")
            print(f"   Reason: {ctx.block_reason}")
            print(f"   Policies: {ctx.policies}")
        else:
            print("✅ Request approved (unexpected)")


if __name__ == "__main__":
    asyncio.run(main())
    asyncio.run(blocked_example())
