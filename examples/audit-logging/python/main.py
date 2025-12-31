"""
AxonFlow Audit Logging - Python

Demonstrates the complete Gateway Mode workflow with audit logging:
1. Pre-check - Validate request against policies
2. LLM Call - Make your own call to OpenAI
3. Audit - Log the interaction for compliance
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from axonflow import AxonFlow

load_dotenv()

# Optional: OpenAI for real LLM calls
try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


async def main():
    print("AxonFlow Audit Logging - Python")
    print("=" * 40)
    print()

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "audit-logging-demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        openai_key = os.getenv("OPENAI_API_KEY", "")
        openai_client = None
        if OPENAI_AVAILABLE and openai_key:
            openai_client = AsyncOpenAI(api_key=openai_key)
        else:
            print("Note: Using mock LLM responses (set OPENAI_API_KEY for real calls)")
            print()

        queries = [
            ("Simple Question", "What is the capital of France?"),
            ("Technical Query", "Explain the CAP theorem in distributed systems."),
            ("Analysis Request", "What are the key benefits of containerization?"),
        ]

        for name, query in queries:
            print(f"Query: {name}")
            print(f'  "{query}"')
            print()

            # Step 1: Pre-check
            print("Step 1: Policy Pre-Check...")
            precheck_start = time.time()

            try:
                precheck = await axonflow.get_policy_approved_context(
                    user_token="audit-user",
                    query=query,
                    context={"example": "audit-logging"},
                )
            except Exception as e:
                print(f"   Error: {e}")
                continue

            precheck_latency = (time.time() - precheck_start) * 1000
            print(f"   Latency: {precheck_latency:.1f}ms")
            print(f"   Context ID: {precheck.context_id}")

            if not precheck.approved:
                print(f"   BLOCKED: {precheck.block_reason}")
                print()
                continue
            print("   Status: APPROVED")
            print()

            # Step 2: LLM Call
            print("Step 2: LLM Call (OpenAI)...")
            llm_start = time.time()

            if openai_client:
                completion = await openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": query}],
                    max_tokens=150,
                )
                response = completion.choices[0].message.content
                prompt_tokens = completion.usage.prompt_tokens
                completion_tokens = completion.usage.completion_tokens
                total_tokens = completion.usage.total_tokens
            else:
                # Mock response
                await asyncio.sleep(0.1)
                response = f"Mock response for: {query}"
                prompt_tokens = 20
                completion_tokens = 30
                total_tokens = 50

            llm_latency = (time.time() - llm_start) * 1000
            print(f"   Latency: {llm_latency:.1f}ms")
            print(f"   Tokens: {prompt_tokens} prompt, {completion_tokens} completion")
            print()

            # Step 3: Audit
            print("Step 3: Audit Logging...")
            audit_start = time.time()

            response_summary = response[:100] + "..." if len(response) > 100 else response

            try:
                audit_result = await axonflow.audit_llm_call(
                    context_id=precheck.context_id,
                    response_summary=response_summary,
                    provider="openai",
                    model="gpt-3.5-turbo",
                    token_usage={
                        "prompt_tokens": prompt_tokens,
                        "completion_tokens": completion_tokens,
                        "total_tokens": total_tokens,
                    },
                    latency_ms=int(llm_latency),
                )
                audit_latency = (time.time() - audit_start) * 1000
                print(f"   Latency: {audit_latency:.1f}ms")
                if audit_result:
                    print(f"   Audit ID: {audit_result.get('audit_id', 'N/A')}")
            except Exception as e:
                audit_latency = (time.time() - audit_start) * 1000
                print(f"   Warning: Audit failed: {e}")

            # Summary
            governance = precheck_latency + audit_latency
            total = precheck_latency + llm_latency + audit_latency

            print()
            print("   Latency Breakdown:")
            print(f"     Pre-check:  {precheck_latency:.1f}ms")
            print(f"     LLM call:   {llm_latency:.1f}ms")
            print(f"     Audit:      {audit_latency:.1f}ms")
            print(f"     Governance: {governance:.1f}ms ({governance/total*100:.1f}% overhead)")
            print(f"     Total:      {total:.1f}ms")
            print()
            print("=" * 40)
            print()

    print("Audit Logging Complete!")
    print()
    print("Query audit logs via Orchestrator API:")
    print("  curl http://localhost:8081/api/v1/audit/tenant/audit-logging-demo")


if __name__ == "__main__":
    asyncio.run(main())
