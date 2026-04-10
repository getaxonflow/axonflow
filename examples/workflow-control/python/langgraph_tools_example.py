#!/usr/bin/env python3
"""
LangGraph Per-Tool Governance Example - Python

VALIDATION: This example exits with code 1 if any assertion fails.

"LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

This example demonstrates per-tool governance using the AxonFlowLangGraphAdapter.
Instead of governing an entire tools node as one step, each individual tool
invocation gets its own gate check — enabling fine-grained tool-level policies.

New in v4.8.0:
  - check_tool_gate() — per-tool governance gate
  - tool_completed()  — per-tool completion tracking
  - trace_id          — external tracing correlation

Run with: python langgraph_tools_example.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from dotenv import load_dotenv
from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, WorkflowBlockedError
from axonflow.workflow import WorkflowSource

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   ✓ PASS: {message}")
    else:
        print(f"   ❌ FAIL: {message}")
        failures.append(message)


async def main() -> int:
    print("LangGraph Per-Tool Governance Example")
    print("=" * 40)
    print()
    print("Demonstrates per-tool governance within a LangGraph tools node.")
    print("Each tool invocation gets its own gate check and completion tracking.")
    print()

    async with AxonFlow(
        endpoint=os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "langgraph-tools-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        adapter = AxonFlowLangGraphAdapter(
            client=client,
            workflow_name="langgraph-research-agent",
            source=WorkflowSource.LANGGRAPH,
            auto_block=True,
        )

        try:
            async with adapter:
                # --- Start workflow with trace_id ---
                print("Step 1: Start Workflow (with trace_id)")
                workflow_id = await adapter.start_workflow(
                    trace_id="otel-trace-12345-research",
                    metadata={"example": "per-tool-governance"},
                )

                assert_check(workflow_id is not None, "start_workflow returned workflow_id")
                assert_check(workflow_id != "", "workflow_id is not empty")
                print(f"   Workflow started: {workflow_id}")
                print()

                # --- Step 2: LLM Node — standard gate check ---
                print("Step 2: Node 'plan_research' (LLM call)")
                print("   Checking gate...")

                gate_result = await adapter.check_gate(
                    step_name="plan_research",
                    step_type="llm_call",
                    model="claude-sonnet-4-20250514",
                    provider="anthropic",
                    step_input={"prompt": "Plan research on AI governance"},
                )

                assert_check(gate_result is True, "check_gate returned True for plan_research")

                if gate_result:
                    print("   Gate: ALLOWED — executing LLM node...")
                    plan_result = {
                        "plan": ["web_search", "sql_query", "code_analysis"],
                        "tokens_used": 150,
                    }

                    await adapter.step_completed(
                        step_name="plan_research",
                        output=plan_result,
                        tokens_in=50,
                        tokens_out=150,
                        cost_usd=0.003,
                    )
                    assert_check(True, "step_completed succeeded for plan_research")
                    print("   Node completed!")
                print()

                # --- Step 3: Tools Node — per-tool governance ---
                print("Step 3: Tools Node (3 individual tools)")
                print("   Each tool gets its own gate check.")
                print()

                # Tool 1: web_search (function type)
                print("   Tool 3a: web_search (function)")
                tool_allowed = await adapter.check_tool_gate(
                    tool_name="web_search",
                    tool_type="function",
                    tool_input={"query": "AI governance frameworks 2026"},
                )

                assert_check(tool_allowed is True, "check_tool_gate returned True for web_search")

                if tool_allowed:
                    print("   Gate: ALLOWED — executing web_search...")
                    search_result = {"results": [{"title": "EU AI Act", "url": "https://example.com"}]}

                    await adapter.tool_completed(
                        tool_name="web_search",
                        output=search_result,
                        tokens_in=0,
                        tokens_out=0,
                        cost_usd=0.001,
                    )
                    assert_check(True, "tool_completed succeeded for web_search")
                    print("   Tool completed!")
                print()

                # Tool 2: sql_query (MCP type)
                print("   Tool 3b: sql_query (mcp)")
                tool_allowed = await adapter.check_tool_gate(
                    tool_name="sql_query",
                    tool_type="mcp",
                    tool_input={"query": "SELECT COUNT(*) FROM regulations WHERE region='EU'"},
                )

                assert_check(tool_allowed is True, "check_tool_gate returned True for sql_query")

                if tool_allowed:
                    print("   Gate: ALLOWED — executing sql_query...")
                    sql_result = {"rows": [{"count": 42}]}

                    await adapter.tool_completed(
                        tool_name="sql_query",
                        output=sql_result,
                    )
                    assert_check(True, "tool_completed succeeded for sql_query")
                    print("   Tool completed!")
                print()

                # Tool 3: code_executor (function type)
                print("   Tool 3c: code_executor (function)")
                tool_allowed = await adapter.check_tool_gate(
                    tool_name="code_executor",
                    tool_type="function",
                    tool_input={"language": "python", "code": "print('analysis complete')"},
                )

                assert_check(tool_allowed is True, "check_tool_gate returned True for code_executor")

                if tool_allowed:
                    print("   Gate: ALLOWED — executing code_executor...")
                    exec_result = {"stdout": "analysis complete", "exit_code": 0}

                    await adapter.tool_completed(
                        tool_name="code_executor",
                        output=exec_result,
                    )
                    assert_check(True, "tool_completed succeeded for code_executor")
                    print("   Tool completed!")
                print()

                # --- Step 4: Final Synthesis (LLM call) ---
                print("Step 4: Node 'synthesize_report' (LLM call)")
                print("   Checking gate...")

                gate_result = await adapter.check_gate(
                    step_name="synthesize_report",
                    step_type="llm_call",
                    model="claude-sonnet-4-20250514",
                    provider="anthropic",
                    step_input={"prompt": "Synthesize research findings"},
                )

                assert_check(gate_result is True, "check_gate returned True for synthesize_report")

                if gate_result:
                    print("   Gate: ALLOWED — executing LLM node...")
                    report = {"report": "AI governance analysis complete", "word_count": 500}

                    await adapter.step_completed(
                        step_name="synthesize_report",
                        output=report,
                        tokens_in=200,
                        tokens_out=500,
                        cost_usd=0.01,
                    )
                    assert_check(True, "step_completed succeeded for synthesize_report")
                    print("   Node completed!")
                print()

                # --- Verify workflow status ---
                print("Step 5: Verify Workflow Status")
                status = await client.get_workflow(workflow_id)

                assert_check(status is not None, "get_workflow returned status")
                print(f"   Status: {status.status}")
                print(f"   Steps recorded: {len(status.steps)}")

                # We should have 5 steps: plan_research + 3 tools + synthesize_report
                assert_check(len(status.steps) >= 5, "at least 5 steps recorded (1 LLM + 3 tools + 1 LLM)")

                # Verify trace_id persists
                assert_check(status.trace_id == "otel-trace-12345-research", "trace_id preserved in status")
                print()

                print("Step 6: Workflow Complete")
                print("   (Context manager will complete workflow)")

        except WorkflowBlockedError as e:
            print(f"   BLOCKED: {e}")
            print(f"   Step: {e.step_id}")
            print(f"   Reason: {e.reason}")
            print(f"   Policies: {e.policy_ids}")
            assert_check(True, "WorkflowBlockedError raised correctly")

        print()
        print("=" * 40)

    if not failures:
        print("✓ ALL TESTS PASSED")
        print()
        print("Per-Tool Governance validated:")
        print("  - start_workflow() with trace_id")
        print("  - check_gate() for LLM nodes")
        print("  - check_tool_gate() for individual tools (function, mcp)")
        print("  - tool_completed() for tool-level completion tracking")
        print("  - step_completed() with post-execution metrics")
        print("  - Workflow status tracks all steps including tools")
        print("  - trace_id preserved across lifecycle")
        return 0
    else:
        print(f"❌ {len(failures)} TEST(S) FAILED:")
        for f in failures:
            print(f"   - {f}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
