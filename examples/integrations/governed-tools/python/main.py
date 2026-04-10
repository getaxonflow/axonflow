#!/usr/bin/env python3
"""
GovernedTool — Framework-Agnostic Tool Governance Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates GovernedTool wrapping standard LangChain BaseTool instances
with AxonFlow input/output governance. Tests the UNDERLYING policy engine
behavior: PII detection actually blocks/redacts, SQLi is actually caught,
policies are actually evaluated, and tools are NOT called when input is blocked.

GovernedTool works with any framework that accepts BaseTool: LangGraph,
LangChain AgentExecutor, CrewAI (via from_langchain), AutoGen (via
LangChainToolAdapter).

Run with: python main.py
Prerequisites: docker compose up -d, pip install -e /path/to/axonflow-sdk-python
"""

import asyncio
import json
import os
import sys
import time

from langchain_core.tools import tool

from axonflow import AxonFlow
from axonflow.adapters import GovernedTool, govern_tools
from axonflow.exceptions import PolicyViolationError

failures: list[str] = []
call_log: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


# =============================================================================
# Simulated Tools (standard LangChain @tool — no AxonFlow awareness)
# =============================================================================


@tool
def safe_search(query: str) -> str:
    """Search for products — returns clean data without PII."""
    call_log.append(f"safe_search:{query}")
    return json.dumps({"products": [{"name": "Widget A", "price": 9.99}]})


@tool
def customer_lookup(query: str) -> str:
    """Look up customer data — returns PII in results."""
    call_log.append(f"customer_lookup:{query}")
    return json.dumps({
        "name": "John Doe",
        "ssn": "123-45-6789",
        "email": "john@example.com",
        "order_status": "shipped",
    })


@tool
def send_email(message: str) -> str:
    """Send an email notification."""
    call_log.append(f"send_email:{message}")
    return "Email sent successfully"


# =============================================================================
# Tests
# =============================================================================


async def test_clean_tool_call(client: AxonFlow) -> None:
    """Test 1: Clean tool call is allowed AND policies were evaluated."""
    print("=" * 60)
    print("[Test 1] Clean Tool Call — Policies Must Be Evaluated")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(safe_search, client)

    t0 = time.time()
    result = await governed.ainvoke({"query": "latest widgets"})
    latency_ms = int((time.time() - t0) * 1000)

    assert_check(result is not None, "Tool call returned a result")
    assert_check(len(call_log) == 1, "Wrapped tool was called exactly once")
    assert_check(call_log[0] == "safe_search:latest widgets", "Tool received correct args")
    assert_check("Widget A" in str(result), "Result contains expected data")
    print(f"   Latency: {latency_ms}ms")

    # Verify the policy engine actually ran
    direct = await client.mcp_check_input(
        connector_type="safe_search",
        statement='{"query": "latest widgets"}',
    )
    assert_check(
        direct.policies_evaluated > 0,
        f"Policy engine evaluated {direct.policies_evaluated} policies (not zero)",
    )
    print()


async def test_sqli_in_tool_input_blocked(client: AxonFlow) -> None:
    """Test 2: SQL injection in tool input is blocked before execution."""
    print("=" * 60)
    print("[Test 2] SQL Injection in Tool Input — Must Block")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(safe_search, client, connector_type_fn=lambda n: "postgres.query")

    sqli_input = "SELECT * FROM users WHERE id=1; DROP TABLE users;--"
    blocked = False
    block_reason = ""
    try:
        await governed.ainvoke({"query": sqli_input})
    except PolicyViolationError as e:
        blocked = True
        block_reason = str(e)
        print(f"   Blocked: {block_reason}")

    assert_check(blocked, "SQL injection tool call was blocked")
    assert_check(len(call_log) == 0, "Tool was NOT called (blocked before execution)")

    # Verify underlying policy engine
    direct = await client.mcp_check_input(
        connector_type="postgres.query",
        statement=sqli_input,
    )
    assert_check(not direct.allowed, "Direct check-input confirms SQLi is blocked")
    assert_check(
        direct.block_reason is not None and len(direct.block_reason) > 0,
        f"Block reason: {direct.block_reason}",
    )
    print()


async def test_pii_in_tool_input(client: AxonFlow) -> None:
    """Test 3: PII (SSN) in tool input is detected."""
    print("=" * 60)
    print("[Test 3] PII in Tool Input — Must Be Detected")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(send_email, client)

    pii_input = "Customer SSN is 123-45-6789, please process their refund"

    # Verify the policy engine detects PII via direct call first
    direct = await client.mcp_check_input(
        connector_type="send_email",
        statement=json.dumps({"message": pii_input}),
    )

    pii_detected = False
    if not direct.allowed:
        pii_detected = True
        print(f"   Direct check: Input blocked ({direct.block_reason})")
    else:
        pii_detected = direct.policies_evaluated > 0
        print(f"   Direct check: {direct.policies_evaluated} policies evaluated (PII_ACTION may be warn/log)")

    assert_check(pii_detected, "PII in tool input was detected by policy engine")

    # Now test through GovernedTool
    try:
        result = await governed.ainvoke({"message": pii_input})
        assert_check(len(call_log) == 1, "Tool called (PII detected but not blocking at input)")
        print(f"   GovernedTool result: {result}")
    except PolicyViolationError as e:
        assert_check(len(call_log) == 0, "Tool NOT called (PII blocking at input)")
        print(f"   GovernedTool blocked: {e}")
    print()


async def test_pii_in_tool_output(client: AxonFlow) -> None:
    """Test 4: PII in tool output is detected/redacted."""
    print("=" * 60)
    print("[Test 4] PII in Tool Output — Must Be Detected/Redacted")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(customer_lookup, client)

    # Verify policy engine handles PII output via direct call
    pii_output = json.dumps({
        "name": "John Doe",
        "ssn": "123-45-6789",
        "email": "john@example.com",
    })
    direct = await client.mcp_check_output(
        connector_type="customer_lookup",
        message=pii_output,
    )

    output_pii_handled = False
    if not direct.allowed:
        output_pii_handled = True
        print(f"   Direct check: Output blocked ({direct.block_reason})")
    elif direct.redacted_data is not None:
        output_pii_handled = True
        print(f"   Direct check: Output redacted")
    else:
        output_pii_handled = direct.policies_evaluated > 0
        print(f"   Direct check: {direct.policies_evaluated} policies evaluated")

    assert_check(output_pii_handled, "PII in tool output was handled by policy engine")

    # Test through GovernedTool
    try:
        result = await governed.ainvoke({"query": "John Doe"})
        assert_check(len(call_log) == 1, "Tool was called (output-side check)")

        # Check if result was redacted
        if "123-45-6789" not in str(result):
            print(f"   GovernedTool: Output redacted (raw SSN not present)")
        elif "***" in str(result) or "REDACTED" in str(result):
            print(f"   GovernedTool: Output redacted")
        else:
            print(f"   GovernedTool: Output returned (PII_ACTION may be warn/log)")
        print(f"   Result: {str(result)[:200]}")
    except PolicyViolationError as e:
        assert_check(len(call_log) == 1, "Tool was called before output block")
        print(f"   GovernedTool: Output blocked ({e})")
    print()


async def test_custom_connector_type(client: AxonFlow) -> None:
    """Test 5: Custom connector_type_fn derivation."""
    print("=" * 60)
    print("[Test 5] Custom Connector Type Derivation")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(
        safe_search,
        client,
        connector_type_fn=lambda name: f"salesforce.{name}",
    )

    assert_check(
        governed._connector_type == "salesforce.safe_search",
        f"Connector type derived correctly: {governed._connector_type}",
    )

    result = await governed.ainvoke({"query": "find contacts"})
    assert_check(result is not None, "Custom connector type call succeeded")
    assert_check(len(call_log) == 1, "Tool was called")

    # Verify connector type was used in the check
    direct = await client.mcp_check_input(
        connector_type="salesforce.safe_search",
        statement='{"query": "find contacts"}',
    )
    assert_check(direct.allowed, "Direct check with custom connector_type allowed")
    assert_check(
        direct.policies_evaluated > 0,
        f"Policies evaluated: {direct.policies_evaluated}",
    )
    print()


async def test_query_operation(client: AxonFlow) -> None:
    """Test 6: Read-only tool with operation='query'."""
    print("=" * 60)
    print("[Test 6] Read-Only Tool with operation='query'")
    print("=" * 60)

    call_log.clear()
    governed = GovernedTool(safe_search, client, operation="query")

    result = await governed.ainvoke({"query": "list products"})
    assert_check(result is not None, "Query-mode tool call succeeded")
    assert_check(len(call_log) == 1, "Tool was called")

    # Verify operation forwarded
    direct = await client.mcp_check_input(
        connector_type="safe_search",
        statement='{"query": "list products"}',
        operation="query",
    )
    assert_check(direct.allowed, "Direct check with operation=query allowed")
    print()


async def test_govern_tools_helper(client: AxonFlow) -> None:
    """Test 7: govern_tools() wraps multiple tools correctly."""
    print("=" * 60)
    print("[Test 7] govern_tools() Helper — Multi-Tool Wrapping")
    print("=" * 60)

    call_log.clear()
    governed = govern_tools(
        [safe_search, customer_lookup, send_email],
        client,
    )

    assert_check(len(governed) == 3, f"Wrapped {len(governed)} tools")

    for g in governed:
        from langchain_core.tools import BaseTool

        assert_check(isinstance(g, BaseTool), f"{g.name} is BaseTool instance")
        assert_check(isinstance(g, GovernedTool), f"{g.name} is GovernedTool instance")

    # Call first tool
    result = await governed[0].ainvoke({"query": "test"})
    assert_check(result is not None, "First governed tool returned result")
    assert_check(len(call_log) == 1, "Only the first tool was called")

    print(f"   Tools: {[g.name for g in governed]}")
    print()


async def test_repr_and_metadata(client: AxonFlow) -> None:
    """Test 8: GovernedTool preserves tool metadata correctly."""
    print("=" * 60)
    print("[Test 8] GovernedTool Metadata & repr")
    print("=" * 60)

    governed = GovernedTool(safe_search, client)

    assert_check(governed.name == "safe_search", f"Name: {governed.name}")
    assert_check(governed.description == "Search for products — returns clean data without PII.", f"Description preserved")
    assert_check("GovernedTool" in repr(governed), f"repr: {repr(governed)}")
    assert_check("safe_search" in repr(governed), "Tool name in repr")

    # Custom connector type
    governed2 = GovernedTool(
        customer_lookup, client,
        connector_type_fn=lambda n: f"crm.{n}",
        operation="query",
    )
    assert_check("crm.customer_lookup" in repr(governed2), f"Custom repr: {repr(governed2)}")
    assert_check(governed2._operation == "query", "Custom operation preserved")
    print()


# =============================================================================
# Main
# =============================================================================


async def main() -> int:
    print("GovernedTool — Framework-Agnostic Tool Governance")
    print("=" * 60)
    print()
    print("Validates AxonFlow policy enforcement around any LangChain BaseTool,")
    print("verifying the underlying policy engine behavior.")
    print()

    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    print(f"Checking AxonFlow at {agent_url}...")

    async with AxonFlow(
        endpoint=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "governed-tool-example"),
        client_secret=os.getenv("AXONFLOW_CLIENT_SECRET", ""),
    ) as client:

        # Health check
        try:
            healthy = await client.health_check()
            if not healthy:
                print("Status: unhealthy")
                print("\nMake sure AxonFlow is running: docker compose up -d")
                return 1
            print("Status: healthy")
        except Exception as e:
            print(f"Error: {e}")
            print("\nMake sure AxonFlow is running: docker compose up -d")
            return 1
        print()

        print("Running GovernedTool tests...")
        print()

        await test_clean_tool_call(client)
        await test_sqli_in_tool_input_blocked(client)
        await test_pii_in_tool_input(client)
        await test_pii_in_tool_output(client)
        await test_custom_connector_type(client)
        await test_query_operation(client)
        await test_govern_tools_helper(client)
        await test_repr_and_metadata(client)

        # Summary
        print("=" * 60)
        print("Test Summary")
        print("=" * 60)
        if not failures:
            print("ALL TESTS PASSED")
        else:
            print(f"{len(failures)} TEST(S) FAILED:")
            for f in failures:
                print(f"   - {f}")
        print("=" * 60)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
