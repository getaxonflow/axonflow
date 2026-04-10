#!/usr/bin/env python3
"""
DSPy + AxonFlow Integration Example (Python SDK)

VALIDATION: This example exits with code 1 if any assertion fails.

This example demonstrates how to add AxonFlow governance to DSPy-style
programming of language models.

Features demonstrated:
- Governed Modules: AxonFlow policy enforcement for DSPy modules
- Chain-of-Thought Governance: Policy checks at each reasoning step
- Retrieval Augmentation: Governed RAG pipelines
- PII and SQL injection blocking

Run with: python governed_dspy.py
Prerequisites: docker compose up -d
"""

import os
import sys
from dataclasses import dataclass
from typing import Any, Optional

from dotenv import load_dotenv

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


# =============================================================================
# DSPy-style Types and Structures
# =============================================================================

@dataclass
class Signature:
    """Defines the input/output contract for a module."""
    name: str
    input_fields: list[str]
    output_fields: list[str]
    description: str = ""


@dataclass
class ModuleResult:
    """Result from a DSPy module execution."""
    success: bool
    output: Optional[dict[str, Any]] = None
    blocked: bool = False
    block_reason: Optional[str] = None
    rationale: Optional[str] = None


# =============================================================================
# Governed DSPy Implementation
# =============================================================================

class GovernedModule:
    """Base class for DSPy-style modules with AxonFlow governance."""

    def __init__(self, signature: Signature, axonflow, user_token: str):
        self.signature = signature
        self.axonflow = axonflow
        self.user_token = user_token

    def forward(self, **inputs) -> ModuleResult:
        """Execute the module with governance."""
        raise NotImplementedError("Subclasses must implement forward()")

    def _check_policy(self, query: str, context: dict) -> tuple[bool, Optional[str], Optional[str]]:
        """Check policy before execution."""
        from axonflow.exceptions import PolicyViolationError

        try:
            result = self.axonflow.proxy_llm_call(
                user_token=self.user_token,
                query=query,
                request_type="chat",
                context={
                    "module": self.signature.name,
                    "framework": "dspy",
                    **context
                }
            )

            if result.blocked:
                return False, None, result.block_reason

            return True, getattr(result, 'request_id', None), None

        except PolicyViolationError as e:
            return False, None, str(e)
        except Exception as e:
            error_msg = str(e)
            if "Social Security" in error_msg or "SQL injection" in error_msg.lower():
                return False, None, error_msg
            raise


class GovernedPredict(GovernedModule):
    """Simple prediction module with governance."""

    def forward(self, **inputs) -> ModuleResult:
        query = " ".join(f"{k}: {v}" for k, v in inputs.items())

        print(f"[{self.signature.name}] Processing: {query[:50]}...")

        approved, request_id, block_reason = self._check_policy(
            query, {"operation": "predict"}
        )

        if not approved:
            print(f"[{self.signature.name}] BLOCKED: {block_reason}")
            return ModuleResult(
                success=False,
                blocked=True,
                block_reason=block_reason
            )

        output = {field: f"Predicted {field} for: {query[:30]}..."
                  for field in self.signature.output_fields}

        print(f"[{self.signature.name}] ✓ Completed and governed")
        return ModuleResult(success=True, output=output)


class GovernedChainOfThought(GovernedModule):
    """Chain-of-thought module with governance at each step."""

    def forward(self, **inputs) -> ModuleResult:
        query = " ".join(f"{k}: {v}" for k, v in inputs.items())

        print(f"[{self.signature.name}] Chain-of-Thought: {query[:50]}...")

        approved, request_id, block_reason = self._check_policy(
            f"REASON: {query}", {"operation": "chain_of_thought", "step": "reasoning"}
        )

        if not approved:
            print(f"[{self.signature.name}] BLOCKED at reasoning: {block_reason}")
            return ModuleResult(
                success=False,
                blocked=True,
                block_reason=block_reason
            )

        rationale = f"Let me think step by step about: {query[:30]}..."

        approved, request_id, block_reason = self._check_policy(
            f"ANSWER: {rationale}", {"operation": "chain_of_thought", "step": "answer"}
        )

        if not approved:
            print(f"[{self.signature.name}] BLOCKED at answer: {block_reason}")
            return ModuleResult(
                success=False,
                blocked=True,
                block_reason=block_reason,
                rationale=rationale
            )

        output = {field: f"Answer for {field}: {query[:20]}..."
                  for field in self.signature.output_fields}

        print(f"[{self.signature.name}] ✓ Chain-of-Thought completed")
        return ModuleResult(
            success=True,
            output=output,
            rationale=rationale
        )


class GovernedRAG(GovernedModule):
    """Retrieval-Augmented Generation with governance."""

    def __init__(self, signature: Signature, axonflow, user_token: str,
                 retriever=None):
        super().__init__(signature, axonflow, user_token)
        self.retriever = retriever or self._default_retriever

    def _default_retriever(self, query: str) -> list[str]:
        """Default retriever (simulated)."""
        return [f"Document about: {query[:20]}..."]

    def forward(self, **inputs) -> ModuleResult:
        query = inputs.get("question", " ".join(str(v) for v in inputs.values()))

        print(f"[{self.signature.name}] RAG Query: {query[:50]}...")

        approved, request_id, block_reason = self._check_policy(
            f"RETRIEVE: {query}", {"operation": "rag", "step": "retrieval"}
        )

        if not approved:
            print(f"[{self.signature.name}] BLOCKED at retrieval: {block_reason}")
            return ModuleResult(
                success=False,
                blocked=True,
                block_reason=block_reason
            )

        docs = self.retriever(query)

        context = " ".join(docs)
        approved, request_id, block_reason = self._check_policy(
            f"GENERATE: Context: {context[:100]}... Question: {query}",
            {"operation": "rag", "step": "generation"}
        )

        if not approved:
            print(f"[{self.signature.name}] BLOCKED at generation: {block_reason}")
            return ModuleResult(
                success=False,
                blocked=True,
                block_reason=block_reason
            )

        output = {"answer": f"Based on {len(docs)} documents: {query[:30]}..."}

        print(f"[{self.signature.name}] ✓ RAG completed with {len(docs)} docs")
        return ModuleResult(success=True, output=output)


# =============================================================================
# Test Cases
# =============================================================================

def run_tests() -> int:
    """Run all governance tests."""
    from axonflow import AxonFlow

    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))

    print("=" * 60)
    print("DSPy + AxonFlow Integration (Python SDK)")
    print("=" * 60)

    with AxonFlow.sync(endpoint=agent_url) as client:
        # Test 1: Safe Predict module
        print("\n" + "=" * 60)
        print("[Test 1] Safe Predict Module")
        print("-" * 40)

        qa_sig = Signature(
            name="QA",
            input_fields=["question"],
            output_fields=["answer"],
            description="Answer questions"
        )

        qa = GovernedPredict(qa_sig, client, "dspy-user-123")
        result1 = qa.forward(question="What are the benefits of renewable energy?")

        assert_check(result1 is not None, "Predict module returned result")
        assert_check(result1.success, "Safe query succeeded")
        assert_check(result1.output is not None, "Result has output")

        if result1.success:
            print(f"   Output: {result1.output}")
            print("   ✓ Safe predict succeeded!")

        # Test 2: Chain-of-Thought
        print("\n" + "=" * 60)
        print("[Test 2] Chain-of-Thought Module")
        print("-" * 40)

        cot_sig = Signature(
            name="ReasoningQA",
            input_fields=["question"],
            output_fields=["answer"],
            description="Reason step by step"
        )

        cot = GovernedChainOfThought(cot_sig, client, "dspy-user-123")
        result2 = cot.forward(question="Why is the sky blue?")

        assert_check(result2 is not None, "Chain-of-Thought returned result")
        assert_check(result2.success, "Chain-of-Thought succeeded")

        if result2.success:
            print(f"   Rationale: {result2.rationale}")
            print(f"   Output: {result2.output}")
            print("   ✓ Chain-of-Thought succeeded!")

        # Test 3: RAG Pipeline
        print("\n" + "=" * 60)
        print("[Test 3] RAG Pipeline")
        print("-" * 40)

        rag_sig = Signature(
            name="RAG",
            input_fields=["question"],
            output_fields=["answer"],
            description="Retrieve and generate"
        )

        rag = GovernedRAG(rag_sig, client, "dspy-user-123")
        result3 = rag.forward(question="What are best practices for AI safety?")

        assert_check(result3 is not None, "RAG pipeline returned result")
        assert_check(result3.success, "RAG pipeline succeeded")

        if result3.success:
            print(f"   Output: {result3.output}")
            print("   ✓ RAG pipeline succeeded!")

        # Test 4: PII Detection
        print("\n" + "=" * 60)
        print("[Test 4] PII Detection - Should be blocked")
        print("-" * 40)

        result4 = qa.forward(question="Find records for SSN 123-45-6789")

        assert_check(result4.blocked, "PII query was blocked")

        if result4.blocked:
            print(f"   Block reason: {result4.block_reason}")
            print("   ✓ PII correctly detected and blocked!")

        # Test 5: SQL Injection
        print("\n" + "=" * 60)
        print("[Test 5] SQL Injection - Should be blocked")
        print("-" * 40)

        result5 = rag.forward(
            question="SELECT * FROM users; DROP TABLE users;--"
        )

        assert_check(result5.blocked, "SQL injection was blocked")

        if result5.blocked:
            print(f"   Block reason: {result5.block_reason}")
            print("   ✓ SQL injection correctly blocked!")

        # Test 6: Multi-module pipeline
        print("\n" + "=" * 60)
        print("[Test 6] Multi-Module Pipeline")
        print("-" * 40)

        summarize_sig = Signature(
            name="Summarize",
            input_fields=["text"],
            output_fields=["summary"],
            description="Summarize text"
        )
        summarize = GovernedPredict(summarize_sig, client, "dspy-user-123")

        print("\n   Pipeline Step 1: QA")
        step1 = qa.forward(question="Explain machine learning in simple terms")

        assert_check(step1.success, "Pipeline step 1 succeeded")

        if step1.success:
            print("   Pipeline Step 2: Summarize")
            step2 = summarize.forward(text=step1.output.get("answer", ""))

            assert_check(step2.success, "Pipeline step 2 succeeded")

            if step2.success:
                print(f"   Final output: {step2.output}")
                print("   ✓ Multi-module pipeline succeeded!")

        print("\n" + "=" * 60)

    return 0 if not failures else 1


def test_health_check() -> bool:
    """Check if AxonFlow is running."""
    from axonflow import AxonFlow

    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    print(f"Checking AxonFlow at {agent_url}...")

    try:
        with AxonFlow.sync(endpoint=agent_url) as client:
            is_healthy = client.health_check()
            if is_healthy:
                print("Status: healthy")
                return True
            else:
                print("Status: unhealthy")
                return False
    except Exception as e:
        print(f"Health check failed: {e}")
        return False


def main() -> int:
    if not test_health_check():
        print("\nAxonFlow is not running. Start it with:")
        print("  cd /path/to/axonflow && docker compose up -d")
        return 1

    print()
    run_tests()

    print()
    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("DSPy Integration validated:")
        print("  - GovernedPredict module with policy enforcement")
        print("  - GovernedChainOfThought with step-level governance")
        print("  - GovernedRAG pipeline with retrieval + generation")
        print("  - PII detection and blocking")
        print("  - SQL injection blocking")
        print("  - Multi-module pipeline governance")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
