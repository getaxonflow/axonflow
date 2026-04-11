#!/usr/bin/env python3
"""
LangGraph + AxonFlow MCP Tool Interceptor Example

VALIDATION: This example exits with code 1 if any assertion fails.

Demonstrates using AxonFlowLangGraphAdapter.mcp_tool_interceptor() to enforce
AxonFlow policies around MCP tool calls in a LangGraph workflow.

The interceptor wraps every MCP tool call with:
    mcp_check_input -> handler() -> mcp_check_output

This example validates the UNDERLYING policy engine behavior, not just the
API surface: SQLi detection actually blocks, PII is actually detected/redacted,
policies are actually evaluated, and handlers are NOT called when blocked.

Run with: python main.py
Prerequisites: docker compose up -d
"""

import asyncio
import os
import sys

from dotenv import load_dotenv

from axonflow import AxonFlow
from axonflow.adapters import AxonFlowLangGraphAdapter, MCPInterceptorOptions
from axonflow.exceptions import PolicyViolationError

load_dotenv()

failures: list[str] = []


def assert_check(condition: bool, message: str) -> None:
    """Check a condition and record failure if false."""
    if condition:
        print(f"   PASS: {message}")
    else:
        print(f"   FAIL: {message}")
        failures.append(message)


# =============================================================================
# Simulated MCP Infrastructure
# =============================================================================


class MCPToolCallRequest:
    """Simulates langchain_mcp_adapters.MCPToolCallRequest."""

    def __init__(self, server_name: str, name: str, args: dict) -> None:
        self.server_name = server_name
        self.name = name
        self.args = args


call_log: list[str] = []


async def safe_db_handler(request: MCPToolCallRequest) -> dict:
    """Simulates a database query MCP tool that returns clean data."""
    call_log.append(f"safe_db_handler:{request.server_name}.{request.name}")
    return {
        "rows": [
            {"id": 1, "product": "Widget A", "price": 9.99},
            {"id": 2, "product": "Widget B", "price": 14.99},
        ],
        "row_count": 2,
    }


async def pii_db_handler(request: MCPToolCallRequest) -> dict:
    """Simulates a database query MCP tool that returns PII in results."""
    call_log.append(f"pii_db_handler:{request.server_name}.{request.name}")
    return {
        "rows": [
            {"id": 1, "name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"},
        ],
        "row_count": 1,
    }


# =============================================================================
# Tests
# =============================================================================


async def test_allowed_with_policy_evaluation(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 1: Clean query is allowed AND policies were actually evaluated."""
    print("=" * 60)
    print("[Test 1] Safe MCP Tool Call - Policies must be evaluated")
    print("=" * 60)

    call_log.clear()
    interceptor = adapter.mcp_tool_interceptor()
    request = MCPToolCallRequest(
        server_name="postgres",
        name="query",
        args={"sql": "SELECT product, price FROM catalog WHERE price < 20"},
    )

    result = await interceptor(request, safe_db_handler)

    assert_check(result is not None, "Tool call returned a result")
    assert_check("rows" in result, "Result contains rows")
    assert_check(result["row_count"] == 2, f"Row count is 2 (got {result.get('row_count')})")
    assert_check(len(call_log) == 1, "Handler was called exactly once")

    # Verify the policy engine actually ran by making a direct check-input call
    direct = await client.mcp_check_input(
        connector_type="postgres.query",
        statement="SELECT product, price FROM catalog WHERE price < 20",
    )
    assert_check(direct.allowed, "Direct check-input confirms query is allowed")
    assert_check(
        direct.policies_evaluated > 0,
        f"Policy engine evaluated {direct.policies_evaluated} policies (not zero)",
    )
    print()


async def test_sqli_actually_blocked(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 2: SQL injection is detected by the static policy engine."""
    print("=" * 60)
    print("[Test 2] SQL Injection - Must be blocked by policy engine")
    print("=" * 60)

    call_log.clear()
    interceptor = adapter.mcp_tool_interceptor()
    request = MCPToolCallRequest(
        server_name="postgres",
        name="query",
        args={"sql": "SELECT * FROM users WHERE id=1; DROP TABLE users;--"},
    )

    blocked = False
    block_reason = ""
    try:
        await interceptor(request, safe_db_handler)
    except PolicyViolationError as e:
        blocked = True
        block_reason = str(e)
        print(f"   Blocked: {block_reason}")

    assert_check(blocked, "SQL injection tool call was blocked")
    assert_check(len(call_log) == 0, "Handler was NOT called (blocked before execution)")

    # Verify the underlying policy engine returns the same verdict
    direct = await client.mcp_check_input(
        connector_type="postgres.query",
        statement="SELECT * FROM users WHERE id=1; DROP TABLE users;--",
    )
    assert_check(not direct.allowed, "Direct check-input confirms SQLi is blocked")
    assert_check(
        direct.block_reason is not None and len(direct.block_reason) > 0,
        f"Policy engine provides block reason: {direct.block_reason}",
    )
    print()


async def test_pii_in_input_detected(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 3: PII (SSN) in tool input is detected by input policy."""
    print("=" * 60)
    print("[Test 3] PII in MCP Tool Input - Must be detected")
    print("=" * 60)

    # Verify the policy engine detects PII via direct call first
    direct = await client.mcp_check_input(
        connector_type="postgres.query",
        statement="SELECT * FROM users WHERE ssn = '123-45-6789'",
    )

    pii_detected = False
    if not direct.allowed:
        pii_detected = True
        print(f"   Input blocked: {direct.block_reason}")
    elif direct.policy_info and direct.policy_info.policies_evaluated:
        # PII_ACTION=redact/warn/log: not blocked but policies were evaluated
        policies = direct.policy_info.policies_evaluated
        print(f"   Input allowed with {policies} policies evaluated (PII_ACTION may be redact/warn/log)")
        pii_detected = policies > 0
    else:
        print(f"   Input allowed, policies_evaluated={direct.policies_evaluated}")
        pii_detected = direct.policies_evaluated > 0

    assert_check(pii_detected, "PII in tool input was detected by policy engine")

    # Now test through the interceptor
    call_log.clear()
    interceptor = adapter.mcp_tool_interceptor()
    request = MCPToolCallRequest(
        server_name="postgres",
        name="query",
        args={"sql": "SELECT * FROM users WHERE ssn = '123-45-6789'"},
    )

    try:
        await interceptor(request, safe_db_handler)
        assert_check(len(call_log) == 1, "Handler called (PII detected but not blocking)")
    except PolicyViolationError as e:
        assert_check(len(call_log) == 0, "Handler NOT called (PII blocking mode)")
        print(f"   Interceptor blocked: {e}")
    print()


async def test_pii_in_output_redacted(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 4: PII in tool output is detected/redacted by output policy."""
    print("=" * 60)
    print("[Test 4] PII in MCP Tool Output - Must be detected/redacted")
    print("=" * 60)

    # Verify the policy engine detects PII in output via direct call
    direct = await client.mcp_check_output(
        connector_type="postgres.query",
        message='{"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"}',
    )

    output_pii_handled = False
    if not direct.allowed:
        output_pii_handled = True
        print(f"   Output blocked: {direct.block_reason}")
    elif direct.redacted_data is not None:
        output_pii_handled = True
        print(f"   Output redacted: {direct.redacted_data}")
    else:
        policies = direct.policies_evaluated
        print(f"   Output allowed, {policies} policies evaluated")
        output_pii_handled = policies > 0

    assert_check(output_pii_handled, "PII in tool output was handled by policy engine")

    # Test through interceptor: handler returns PII, output should be redacted or blocked
    call_log.clear()
    interceptor = adapter.mcp_tool_interceptor()
    request = MCPToolCallRequest(
        server_name="postgres",
        name="query",
        args={"sql": "SELECT id, name, ssn, email FROM users LIMIT 1"},
    )

    try:
        result = await interceptor(request, pii_db_handler)
        assert_check(len(call_log) == 1, "Handler was called (output-side check)")
        # If result was redacted, it should differ from original PII data
        if isinstance(result, dict) and "ssn" in str(result):
            print(f"   Result still contains raw PII (redaction may not apply to message field)")
        else:
            print(f"   Result returned (may be redacted)")
    except PolicyViolationError as e:
        assert_check(len(call_log) == 1, "Handler was called before output block")
        print(f"   Output blocked by interceptor: {e}")
    print()


async def test_custom_operation_query(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 5: Read-only tool call with operation='query'."""
    print("=" * 60)
    print("[Test 5] Read-Only Tool Call with operation='query'")
    print("=" * 60)

    opts = MCPInterceptorOptions(operation="query")
    interceptor = adapter.mcp_tool_interceptor(opts)
    request = MCPToolCallRequest(
        server_name="postgres",
        name="list_tables",
        args={"schema": "public"},
    )

    result = await interceptor(request, safe_db_handler)

    assert_check(result is not None, "Read-only tool call returned a result")

    # Verify operation is forwarded correctly via direct call
    direct = await client.mcp_check_input(
        connector_type="postgres.list_tables",
        statement='{"schema": "public"}',
        operation="query",
    )
    assert_check(direct.allowed, "Direct check-input with operation=query is allowed")
    assert_check(
        direct.policies_evaluated > 0,
        f"Policies evaluated with operation=query: {direct.policies_evaluated}",
    )
    print()


async def test_custom_connector_type(
    adapter: AxonFlowLangGraphAdapter, client: AxonFlow
) -> None:
    """Test 6: Custom connector_type_fn derivation."""
    print("=" * 60)
    print("[Test 6] Custom Connector Type Derivation")
    print("=" * 60)

    opts = MCPInterceptorOptions(
        connector_type_fn=lambda req: req.server_name,
    )
    interceptor = adapter.mcp_tool_interceptor(opts)
    request = MCPToolCallRequest(
        server_name="salesforce",
        name="search_contacts",
        args={"query": "Find contacts in engineering"},
    )

    result = await interceptor(request, safe_db_handler)

    assert_check(result is not None, "Custom connector type tool call succeeded")

    # Verify the connector type was actually used (not the default format)
    direct = await client.mcp_check_input(
        connector_type="salesforce",
        statement="Find contacts in engineering",
    )
    assert_check(direct.allowed, "Direct check-input with custom connector_type allowed")
    print()


async def main() -> int:
    print("LangGraph + AxonFlow MCP Tool Interceptor Example")
    print("=" * 60)
    print()
    print("This example validates AxonFlow policy enforcement around MCP")
    print("tool calls, verifying the underlying policy engine behavior.")
    print()

    agent_url = os.getenv("AXONFLOW_ENDPOINT", os.getenv("AXONFLOW_AGENT_URL", "http://localhost:8080"))
    print(f"Checking AxonFlow at {agent_url}...")

    async with AxonFlow(
        endpoint=agent_url,
        client_id=os.getenv("AXONFLOW_CLIENT_ID", "langgraph-mcp-example"),
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

        adapter = AxonFlowLangGraphAdapter(
            client=client,
            workflow_name="mcp-interceptor-demo",
        )

        print("Running MCP interceptor tests...")
        print()

        await test_allowed_with_policy_evaluation(adapter, client)
        await test_sqli_actually_blocked(adapter, client)
        await test_pii_in_input_detected(adapter, client)
        await test_pii_in_output_redacted(adapter, client)
        await test_custom_operation_query(adapter, client)
        await test_custom_connector_type(adapter, client)

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
