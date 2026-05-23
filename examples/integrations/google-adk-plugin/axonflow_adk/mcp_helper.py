# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""ADK `MCPToolset` helper for the AxonFlow agent's MCP server.

The AxonFlow agent ships an MCP endpoint at `/mcp/` on the same host as
its REST API. This module returns an `McpToolset` configured against that
endpoint over Streamable HTTP, so ADK callers can register AxonFlow's
governed MCP tools (e.g. PostgreSQL, Snowflake, GCS) with one line:

    from axonflow_adk import axonflow_mcp_toolset

    toolset = axonflow_mcp_toolset(
        endpoint="http://localhost:8080",
        client_id="my-app",
        client_secret="...",
    )

Reference: https://adk.dev/tools-custom/mcp-tools/
"""

from __future__ import annotations

import base64
from typing import Any


def axonflow_mcp_toolset(
    endpoint: str,
    *,
    client_id: str | None = None,
    client_secret: str | None = None,
    bearer_token: str | None = None,
    mcp_path: str = "/mcp/",
    extra_headers: dict[str, str] | None = None,
) -> Any:
    """Return an ADK `McpToolset` pointed at AxonFlow's MCP server.

    Authentication shape (R3 HIGH-3 — the platform's MCP server expects
    one of):

      * `Authorization: Basic <base64(client_id:client_secret)>` when
        `client_id` AND `client_secret` are provided.
      * `Authorization: Bearer <token>` when `bearer_token` is provided.
      * Anonymous (no header) when none are provided — community-mode.

    Custom `X-AxonFlow-*` headers (a prior shape) are NOT recognized by
    the platform and would result in silently-anonymous calls bypassing
    per-client / per-tenant policy scoping. Use the canonical
    Authorization header instead.

    Args:
        endpoint: AxonFlow agent base URL (e.g. `http://localhost:8080`).
            Trailing slash is stripped; `mcp_path` is appended.
        client_id: AxonFlow client identifier (community/enterprise).
        client_secret: AxonFlow client secret (community/enterprise).
        bearer_token: Pre-issued bearer token (overrides client_id/secret
            when set).
        mcp_path: Path component of the AxonFlow MCP endpoint. Defaults
            to `/mcp/` which is the agent's canonical path.
        extra_headers: Optional additional headers (tenant scoping,
            tracing context) merged into the connection params.

    Returns:
        `McpToolset` ready to drop into `LlmAgent(tools=[...])`.

    Raises:
        ImportError: if `google-adk` is not installed.
    """
    from google.adk.tools.mcp_tool import McpToolset
    from google.adk.tools.mcp_tool.mcp_session_manager import (
        StreamableHTTPConnectionParams,
    )

    headers: dict[str, str] = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    elif client_id and client_secret:
        raw = f"{client_id}:{client_secret}".encode()
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    if extra_headers:
        headers.update(extra_headers)

    url = endpoint.rstrip("/") + mcp_path
    return McpToolset(
        connection_params=StreamableHTTPConnectionParams(
            url=url,
            headers=headers,
        )
    )
