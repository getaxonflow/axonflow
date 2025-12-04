"""AxonFlow Python SDK - Enterprise AI Governance in 3 Lines of Code.

This SDK provides a simple, async-first interface for integrating AI governance
into your Python applications. It supports policy enforcement, audit logging,
MCP connectors, and multi-agent planning.

Example:
    >>> from axonflow import AxonFlow
    >>>
    >>> # Async usage
    >>> async with AxonFlow(
    ...     agent_url="https://your-agent.axonflow.com",
    ...     client_id="your-client-id",
    ...     client_secret="your-client-secret"
    ... ) as client:
    ...     result = await client.execute_query("user-token", "What is AI?", "chat")
    ...     print(result.data)
    >>>
    >>> # Sync usage
    >>> client = AxonFlow.sync(
    ...     agent_url="https://your-agent.axonflow.com",
    ...     client_id="your-client-id",
    ...     client_secret="your-client-secret"
    ... )
    >>> result = client.execute_query("user-token", "What is AI?", "chat")
"""

from axonflow.client import AxonFlow, SyncAxonFlow
from axonflow.exceptions import (
    AuthenticationError,
    AxonFlowError,
    ConfigurationError,
    ConnectionError,
    ConnectorError,
    PlanExecutionError,
    PolicyViolationError,
    RateLimitError,
    TimeoutError,
)
from axonflow.types import (
    AuditResult,
    CacheConfig,
    ClientRequest,
    ClientResponse,
    ConnectorInstallRequest,
    ConnectorMetadata,
    ConnectorResponse,
    Mode,
    PlanExecutionResponse,
    PlanResponse,
    PlanStep,
    PolicyApprovalResult,
    PolicyEvaluationInfo,
    RateLimitInfo,
    RetryConfig,
    TokenUsage,
)

__version__ = "0.1.0"
__all__ = [
    # Main client
    "AxonFlow",
    "SyncAxonFlow",
    # Configuration
    "Mode",
    "RetryConfig",
    "CacheConfig",
    # Request/Response types
    "ClientRequest",
    "ClientResponse",
    "PolicyEvaluationInfo",
    # Connector types
    "ConnectorMetadata",
    "ConnectorInstallRequest",
    "ConnectorResponse",
    # Planning types
    "PlanStep",
    "PlanResponse",
    "PlanExecutionResponse",
    # Gateway Mode types
    "RateLimitInfo",
    "PolicyApprovalResult",
    "TokenUsage",
    "AuditResult",
    # Exceptions
    "AxonFlowError",
    "ConfigurationError",
    "AuthenticationError",
    "PolicyViolationError",
    "RateLimitError",
    "ConnectionError",
    "TimeoutError",
    "ConnectorError",
    "PlanExecutionError",
]
