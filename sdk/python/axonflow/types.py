"""AxonFlow SDK Type Definitions.

All types are defined using Pydantic v2 for runtime validation
and automatic JSON serialization/deserialization.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Mode(str, Enum):
    """SDK operation mode."""

    PRODUCTION = "production"
    SANDBOX = "sandbox"


class RetryConfig(BaseModel):
    """Retry configuration with exponential backoff."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(default=True, description="Enable retry logic")
    max_attempts: int = Field(default=3, ge=1, le=10, description="Max retry attempts")
    initial_delay: float = Field(default=1.0, gt=0, description="Initial delay (seconds)")
    max_delay: float = Field(default=30.0, gt=0, description="Max delay (seconds)")
    exponential_base: float = Field(default=2.0, gt=1, description="Backoff multiplier")


class CacheConfig(BaseModel):
    """Cache configuration."""

    model_config = ConfigDict(frozen=True)

    enabled: bool = Field(default=True, description="Enable caching")
    ttl: float = Field(default=60.0, gt=0, description="Cache TTL (seconds)")
    max_size: int = Field(default=1000, gt=0, description="Max cache entries")


class AxonFlowConfig(BaseModel):
    """Configuration for AxonFlow client.

    Attributes:
        agent_url: AxonFlow Agent URL (required)
        client_id: Client ID for authentication (required)
        client_secret: Client secret for authentication (required)
        license_key: Optional license key for organization-level auth
        mode: Operation mode (production or sandbox)
        debug: Enable debug logging
        timeout: Request timeout in seconds
        insecure_skip_verify: Skip TLS verification (dev only)
        retry: Retry configuration
        cache: Cache configuration
    """

    model_config = ConfigDict(frozen=True)

    agent_url: str = Field(..., min_length=1, description="AxonFlow Agent URL")
    client_id: str = Field(..., min_length=1, description="Client ID")
    client_secret: str = Field(..., min_length=1, description="Client secret")
    license_key: str | None = Field(default=None, description="License key")
    mode: Mode = Field(default=Mode.PRODUCTION, description="Operation mode")
    debug: bool = Field(default=False, description="Enable debug logging")
    timeout: float = Field(default=60.0, gt=0, description="Request timeout (seconds)")
    insecure_skip_verify: bool = Field(default=False, description="Skip TLS verify")
    retry: RetryConfig = Field(default_factory=RetryConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)


class ClientRequest(BaseModel):
    """Request to AxonFlow Agent."""

    query: str = Field(..., description="Query or prompt")
    user_token: str = Field(..., description="User token for auth")
    client_id: str = Field(..., description="Client ID")
    request_type: str = Field(..., description="Request type")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")


class PolicyEvaluationInfo(BaseModel):
    """Policy evaluation metadata."""

    policies_evaluated: list[str] = Field(default_factory=list)
    static_checks: list[str] = Field(default_factory=list)
    processing_time: str = Field(default="0ms")
    tenant_id: str = Field(default="")


class ClientResponse(BaseModel):
    """Response from AxonFlow Agent."""

    success: bool = Field(..., description="Whether request succeeded")
    data: Any | None = Field(default=None, description="Response data")
    result: str | None = Field(default=None, description="Result for planning")
    plan_id: str | None = Field(default=None, description="Plan ID if applicable")
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = Field(default=None, description="Error message if failed")
    blocked: bool = Field(default=False, description="Whether request was blocked")
    block_reason: str | None = Field(default=None, description="Block reason")
    policy_info: PolicyEvaluationInfo | None = Field(default=None)


class ConnectorMetadata(BaseModel):
    """MCP connector metadata."""

    id: str
    name: str
    type: str
    version: str = ""
    description: str = ""
    category: str = ""
    icon: str = ""
    tags: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    config_schema: dict[str, Any] = Field(default_factory=dict)
    installed: bool = False
    healthy: bool = False


class ConnectorInstallRequest(BaseModel):
    """Request to install an MCP connector."""

    connector_id: str
    name: str
    tenant_id: str
    options: dict[str, Any] = Field(default_factory=dict)
    credentials: dict[str, str] = Field(default_factory=dict)


class ConnectorResponse(BaseModel):
    """Response from MCP connector query."""

    success: bool
    data: Any | None = None
    error: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class PlanStep(BaseModel):
    """A step in a multi-agent plan."""

    id: str
    name: str
    type: str
    description: str = ""
    depends_on: list[str] = Field(default_factory=list)
    agent: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class PlanResponse(BaseModel):
    """Multi-agent plan response."""

    plan_id: str
    steps: list[PlanStep] = Field(default_factory=list)
    domain: str = "generic"
    complexity: int = 0
    parallel: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class PlanExecutionResponse(BaseModel):
    """Plan execution result."""

    plan_id: str
    status: str  # "running", "completed", "failed"
    result: str | None = None
    step_results: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    duration: str | None = None


# Gateway Mode Types


class RateLimitInfo(BaseModel):
    """Rate limiting status."""

    limit: int
    remaining: int
    reset_at: datetime


class PolicyApprovalResult(BaseModel):
    """Pre-check result from Gateway Mode."""

    context_id: str = Field(..., description="Context ID for audit linking")
    approved: bool = Field(..., description="Whether request is approved")
    approved_data: dict[str, Any] = Field(default_factory=dict)
    policies: list[str] = Field(default_factory=list)
    rate_limit_info: RateLimitInfo | None = None
    expires_at: datetime
    block_reason: str | None = None


class TokenUsage(BaseModel):
    """LLM token usage tracking."""

    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class AuditResult(BaseModel):
    """Audit confirmation."""

    success: bool
    audit_id: str
