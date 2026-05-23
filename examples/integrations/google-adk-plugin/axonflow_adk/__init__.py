# Copyright 2026 AxonFlow
# SPDX-License-Identifier: Apache-2.0

"""AxonFlow governance plugin for Google Agent Development Kit (ADK).

Register `AxonFlowPlugin` on a `Runner` and every model + tool call across
every agent on that runner is governed by AxonFlow policies, with HITL
approval, denial short-circuits, and an audit trail.

    from google.adk.runners import InMemoryRunner
    from axonflow_adk import AxonFlowPlugin

    runner = InMemoryRunner(
        agent=root_agent,
        app_name="loan_desk",
        plugins=[AxonFlowPlugin(
            endpoint="http://localhost:8080",
            client_id="loan-desk",
            client_secret="...",
        )],
    )
"""

from axonflow_adk.plugin import AxonFlowPlugin, ApprovalTimeout, ApprovalRejected
from axonflow_adk.mcp_helper import axonflow_mcp_toolset

__all__ = [
    "ApprovalRejected",
    "ApprovalTimeout",
    "AxonFlowPlugin",
    "axonflow_mcp_toolset",
]
