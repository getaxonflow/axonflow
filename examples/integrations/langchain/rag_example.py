"""
AxonFlow + LangChain RAG (Retrieval-Augmented Generation)

Shows how to add governance to RAG pipelines:
1. Pre-check the user query before retrieval
2. Execute RAG pipeline (retrieve + generate)
3. Audit the response

This ensures queries are validated BEFORE accessing your knowledge base.
"""

import asyncio
import os
import time

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.runnables import RunnablePassthrough

from axonflow import AxonFlow
from axonflow.types import TokenUsage

load_dotenv()


# Simulated knowledge base (replace with your actual retriever)
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


async def main():
    print("AxonFlow + LangChain RAG Example")
    print()

    # Build RAG chain
    llm = ChatOpenAI(
        model="gpt-3.5-turbo",
        temperature=0,
        openai_api_key=os.getenv("OPENAI_API_KEY"),
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
        agent_url=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
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

            # =========================================================
            # Pre-check: Validate query BEFORE accessing knowledge base
            # =========================================================
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

            if not ctx.approved:
                print(f"  BLOCKED: {ctx.block_reason}")
                print("  Query denied access to knowledge base")
                continue

            print(f"  Approved in {pre_check_ms}ms")

            # =========================================================
            # RAG Pipeline: Retrieve + Generate
            # =========================================================
            print("\n[RAG Pipeline] Retrieving and generating...")
            llm_start = time.time()

            result = rag_chain.invoke({"question": question})

            llm_ms = int((time.time() - llm_start) * 1000)
            print(f"  Completed in {llm_ms}ms")

            # =========================================================
            # Audit: Log the interaction
            # =========================================================
            print("\n[Audit] Logging interaction...")
            audit_start = time.time()

            await axonflow.audit_llm_call(
                context_id=ctx.context_id,
                response_summary=result[:100],
                provider="openai",
                model="gpt-3.5-turbo",
                token_usage=TokenUsage(
                    prompt_tokens=0,
                    completion_tokens=0,
                    total_tokens=0,
                ),
                latency_ms=llm_ms,
            )
            audit_ms = int((time.time() - audit_start) * 1000)
            print(f"  Logged in {audit_ms}ms")

            # =========================================================
            # Response
            # =========================================================
            print(f"\n[Answer]\n{result}")
            print(f"\nGovernance overhead: {pre_check_ms + audit_ms}ms")


if __name__ == "__main__":
    asyncio.run(main())
