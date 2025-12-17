"""
AxonFlow + LangChain Chains

Shows how to wrap LangChain chains with AxonFlow governance.
Each chain execution is pre-checked and audited.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


async def main():
    print("AxonFlow + LangChain Chains Example")
    print()

    # Build a LangChain chain
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0.7,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", "You are a helpful assistant that explains concepts simply. Keep responses under 100 words."),
        ("human", "{topic}"),
    ])

    chain = prompt | llm | StrOutputParser()

    async with AxonFlow(
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        # Example topics to process
        topics = [
            "machine learning",
            "neural networks",
            "data governance",
        ]

        for i, topic in enumerate(topics, 1):
            print(f"\n{'=' * 60}")
            print(f"Query {i}: {topic}")
            print("=" * 60)

            # Pre-check
            print("\n[Pre-check]")
            pre_check_start = time.time()

            ctx = await axonflow.get_policy_approved_context(
                user_token="chain-demo-user",
                query=topic,
                context={"chain_type": "explanation", "index": i},
            )
            pre_check_ms = int((time.time() - pre_check_start) * 1000)

            if not ctx.approved:
                print(f"  Blocked: {ctx.block_reason}")
                continue

            print(f"  Approved in {pre_check_ms}ms")
            print(f"  Context ID: {ctx.context_id}")

            # Run chain
            print("\n[LangChain]")
            llm_start = time.time()
            result = chain.invoke({"topic": topic})
            llm_ms = int((time.time() - llm_start) * 1000)

            print(f"  Completed in {llm_ms}ms")

            # Audit
            print("\n[Audit]")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=result[:100],
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=0,  # Not available from chain output
                    completion_tokens=0,
                    total_tokens=0,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)
            print(f"  Logged in {audit_ms}ms")

            # Response
            print(f"\n[Response]\n{result}")
            print(f"\nGovernance overhead: {pre_check_ms + audit_ms}ms")


if __name__ == "__main__":
    asyncio.run(main())
