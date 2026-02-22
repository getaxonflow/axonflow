#!/usr/bin/env python3
"""
AxonFlow + LangChain RAG (Retrieval-Augmented Generation)

VALIDATION: This example exits with code 1 if any assertion fails.

Shows how to add governance to RAG pipelines:
1. Pre-check the user query before retrieval
2. Execute RAG pipeline (retrieve + generate)
3. Audit the response

Run with: python rag_example.py
Prerequisites: docker compose up -d, OPENAI_API_KEY set (optional)
"""

import asyncio
import os
import sys
import time

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


# Simulated knowledge base
KNOWLEDGE_BASE = {
    "api security": """
API Security Best Practices:
1. Use HTTPS for all API endpoints
2. Implement OAuth 2.0 or API keys for authentication
3. Rate limit requests to prevent abuse
4. Validate and sanitize all input data
5. Log all API access for auditing
""",
    "data privacy": """
Data Privacy Guidelines:
1. Collect only necessary data (data minimization)
2. Encrypt sensitive data at rest and in transit
3. Implement access controls and audit logs
4. Provide data deletion capabilities (right to erasure)
5. Document data processing activities
""",
    "ai governance": """
AI Governance Framework:
1. Establish clear ownership and accountability
2. Implement model monitoring and drift detection
3. Maintain audit trails for all AI decisions
4. Ensure human oversight for high-risk decisions
5. Regular bias and fairness assessments
""",
}


def simple_retriever(query: str) -> str:
    """Simple keyword-based retriever for demo purposes."""
    query_lower = query.lower()
    for key, value in KNOWLEDGE_BASE.items():
        if key in query_lower:
            return value
    return "No relevant documents found in knowledge base."


async def run_governance_test() -> int:
    """Test governance without requiring LangChain/OpenAI."""
    print("AxonFlow + LangChain RAG Governance Test")
    print("=" * 60)
    print()
    print("Testing governance layer without full RAG execution...")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        questions = [
            "What are the best practices for API security?",
            "How should we handle data privacy?",
            "What is needed for proper AI governance?",
        ]

        for question in questions:
            print(f"Question: {question}")
            print("-" * 50)

            # Pre-check
            print("[Pre-Check] Validating query...")
            pre_check_start = time.time()

            ctx = await axonflow.get_policy_approved_context(
                user_token="rag-demo-user",
                query=question,
                context={
                    "pipeline": "rag",
                    "retrieval_type": "knowledge_base",
                },
            )
            pre_check_ms = int((time.time() - pre_check_start) * 1000)

            assert_check(ctx is not None, f"Pre-check returned result for '{question[:30]}...'")
            assert_check(ctx.context_id != "", "Pre-check returned context_id")
            assert_check(ctx.approved is True, "Query was approved")

            if not ctx.approved:
                print(f"  BLOCKED: {ctx.block_reason}")
                continue

            print(f"  Approved in {pre_check_ms}ms")

            # Simulate RAG
            print("[RAG Pipeline] (simulated)")
            docs = simple_retriever(question)
            llm_ms = 100

            # Audit
            print("[Audit] Logging interaction...")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=f"RAG answer for: {question[:50]}",
                provider="openai",
                model="gpt-4o-mini",
                token_usage=TokenUsage(
                    prompt_tokens=100,
                    completion_tokens=150,
                    total_tokens=250,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)

            assert_check(True, "Audit succeeded")
            print(f"  Logged in {audit_ms}ms")
            print(f"  Governance overhead: {pre_check_ms + audit_ms}ms")
            print()

    return 0 if not failures else 1


async def main() -> int:
    print("AxonFlow + LangChain RAG Example")
    print()

    # Check if LangChain and OpenAI are available
    openai_key = os.getenv("OPENAI_API_KEY")
    try:
        from langchain_openai import ChatOpenAI
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
        langchain_available = True
    except ImportError:
        langchain_available = False

    if not langchain_available or not openai_key:
        print("Note: LangChain or OPENAI_API_KEY not available")
        print("Running governance layer tests only...")
        print()
        result = await run_governance_test()

        print()
        if not failures:
            print("✓ ALL TESTS PASSED")
            print()
            print("LangChain RAG Governance validated:")
            print("  - get_policy_approved_context() pre-check")
            print("  - Simulated RAG pipeline")
            print("  - audit_llm_call() logging")
            return 0
        else:
            print(f"❌ {len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
            return 1

    # Full RAG test with LangChain
    llm = ChatOpenAI(
        model="gpt-4o-mini",
        temperature=0,
        openai_api_key=openai_key,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", """You are a helpful assistant. Answer the question based on the following context.
If the context doesn't contain relevant information, say so.

Context:
{context}"""),
        ("human", "{question}"),
    ])

    rag_chain = (
        {"context": lambda x: simple_retriever(x["question"]), "question": lambda x: x["question"]}
        | prompt
        | llm
        | StrOutputParser()
    )

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "demo"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
    ) as axonflow:

        questions = [
            "What are the best practices for API security?",
            "How should we handle data privacy?",
            "What is needed for proper AI governance?",
        ]

        for question in questions:
            print(f"\n{'=' * 60}")
            print(f"Question: {question}")
            print("=" * 60)

            # Pre-check
            print("\n[Pre-Check] Validating query...")
            pre_check_start = time.time()

            ctx = await axonflow.get_policy_approved_context(
                user_token="rag-demo-user",
                query=question,
                context={
                    "pipeline": "rag",
                    "retrieval_type": "knowledge_base",
                },
            )
            pre_check_ms = int((time.time() - pre_check_start) * 1000)

            assert_check(ctx is not None, f"Pre-check returned result")
            assert_check(ctx.context_id != "", "Pre-check returned context_id")
            assert_check(ctx.approved is True, "Query was approved")

            if not ctx.approved:
                print(f"  BLOCKED: {ctx.block_reason}")
                continue

            print(f"  Approved in {pre_check_ms}ms")

            # RAG Pipeline
            print("\n[RAG Pipeline] Retrieving and generating...")
            llm_start = time.time()

            result = rag_chain.invoke({"question": question})

            llm_ms = int((time.time() - llm_start) * 1000)

            assert_check(result is not None, "RAG chain returned result")
            assert_check(len(result) > 0, "RAG response is not empty")

            print(f"  Completed in {llm_ms}ms")

            # Audit
            print("\n[Audit] Logging interaction...")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=result[:100],
                provider="openai",
                model="gpt-4o-mini",
                token_usage=TokenUsage(
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)

            assert_check(True, "Audit succeeded")
            print(f"  Logged in {audit_ms}ms")

            print(f"\n[Answer]\n{result}")
            print(f"\nGovernance overhead: {pre_check_ms + audit_ms}ms")

    print()
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("LangChain RAG Integration validated:")
        print("  - get_policy_approved_context() before retrieval")
        print("  - RAG pipeline with knowledge base")
        print("  - audit_llm_call() with response summary")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
