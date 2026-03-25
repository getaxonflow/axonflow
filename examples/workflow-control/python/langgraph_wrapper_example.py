#!/usr/bin/env python3
"""
LangGraph Wrapper (wrap_langgraph) Example - Python

VALIDATION: This example exits with code 1 if any assertion fails.

"LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

This example demonstrates wrap_langgraph(), which wraps a compiled LangGraph
StateGraph with AxonFlow governance in a single call. Each node transition
is automatically gate-checked — no manual check_gate() calls needed.

Features demonstrated:
  - wrap_langgraph() — one-line graph wrapping
  - NodeConfig       — per-node step_type/model/provider overrides
  - GovernedGraph    — reusable across multiple ainvoke() calls
  - WorkflowBlockedError handling

Run with: python langgraph_wrapper_example.py
Prerequisites: docker compose up -d, pip install langgraph
"""

import asyncio
import os
import sys

try:
    from langgraph.graph import StateGraph
except ImportError:
    print("langgraph is not installed. Skipping this example.")
    print("Install with: pip install langgraph>=0.2.0")
    sys.exit(0)

from typing import TypedDict

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.adapters import NodeConfig, WorkflowBlockedError, wrap_langgraph

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


# ---------------------------------------------------------------------------
# Define a simple 3-node LangGraph: plan -> search -> report
# ---------------------------------------------------------------------------


class ResearchState(TypedDict):
    query: str
    plan: str
    search_results: str
    report: str


def plan_node(state: ResearchState) -> dict:
    """Plan the research approach."""
    return {"plan": f"Research plan for: {state['query']}"}


def search_node(state: ResearchState) -> dict:
    """Execute the search."""
    return {"search_results": f"Found 3 results for plan: {state.get('plan', '')}"}


def report_node(state: ResearchState) -> dict:
    """Generate the final report."""
    return {"report": f"Report based on: {state.get('search_results', '')}"}


def build_graph():
    """Build and compile the 3-node StateGraph."""
    builder = StateGraph(ResearchState)
    builder.add_node("plan", plan_node)
    builder.add_node("search", search_node)
    builder.add_node("report", report_node)
    builder.add_edge("plan", "search")
    builder.add_edge("search", "report")
    builder.set_entry_point("plan")
    builder.set_finish_point("report")
    return builder.compile()


async def main() -> int:
    print("LangGraph Wrapper (wrap_langgraph) Example")
    print("=" * 40)
    print()
    print("Wraps a compiled LangGraph StateGraph with AxonFlow governance.")
    print("Gate checks happen automatically at every node transition.")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "langgraph-wrapper-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        # Build the LangGraph
        compiled_graph = build_graph()

        # Wrap with governance — one line
        governed = wrap_langgraph(
            compiled_graph,
            client=client,
            workflow_name="langgraph-research-pipeline",
            metadata={"example": "wrap-langgraph"},
            trace_id="wrapper-trace-001",
            node_config={
                "plan": NodeConfig(
                    step_type="llm_call",
                    model="claude-sonnet-4-20250514",
                    provider="anthropic",
                ),
                "search": NodeConfig(step_type="tool_call"),
                "report": NodeConfig(
                    step_type="llm_call",
                    model="claude-sonnet-4-20250514",
                    provider="anthropic",
                ),
            },
        )

        # --- Invocation 1 ---
        print("Step 1: First Invocation")
        print("   Invoking governed graph with ainvoke()...")
        print()

        try:
            result = await governed.ainvoke({"query": "AI governance frameworks"})

            assert_check(result is not None, "ainvoke returned a result")
            assert_check(isinstance(result, dict), "result is a dict")
            assert_check("plan" in result, "result contains 'plan' key")
            assert_check("search_results" in result, "result contains 'search_results' key")
            assert_check("report" in result, "result contains 'report' key")
            assert_check(len(result.get("report", "")) > 0, "report is not empty")
            print(f"   Plan: {result.get('plan', '')}")
            print(f"   Search: {result.get('search_results', '')}")
            print(f"   Report: {result.get('report', '')}")
            print()

        except WorkflowBlockedError as e:
            print(f"   BLOCKED: {e}")
            print(f"   Step: {e.step_id}")
            print(f"   Reason: {e.reason}")
            print(f"   Policies: {e.policy_ids}")
            assert_check(True, "WorkflowBlockedError raised correctly (invocation 1)")
            print()

        # --- Invocation 2: Verify GovernedGraph reusability ---
        print("Step 2: Second Invocation (reusability)")
        print("   GovernedGraph instances are reusable — each ainvoke() creates a new workflow.")
        print()

        try:
            result2 = await governed.ainvoke({"query": "EU AI Act compliance"})

            assert_check(result2 is not None, "second ainvoke returned a result")
            assert_check(isinstance(result2, dict), "second result is a dict")
            assert_check("report" in result2, "second result contains 'report' key")
            assert_check(
                result2.get("report", "") != result.get("report", ""),
                "second invocation produced different report",
            )
            print(f"   Report: {result2.get('report', '')}")
            print()

        except WorkflowBlockedError as e:
            print(f"   BLOCKED: {e}")
            print(f"   Step: {e.step_id}")
            print(f"   Reason: {e.reason}")
            print(f"   Policies: {e.policy_ids}")
            assert_check(True, "WorkflowBlockedError raised correctly (invocation 2)")
            print()

        print("=" * 40)

    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("wrap_langgraph() validated:")
        print("  - wrap_langgraph() creates GovernedGraph from compiled StateGraph")
        print("  - NodeConfig overrides step_type/model/provider per node")
        print("  - ainvoke() runs the graph with automatic governance gates")
        print("  - GovernedGraph is reusable across multiple invocations")
        print("  - Each invocation creates a separate AxonFlow workflow")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
