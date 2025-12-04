"""Tests for type definitions and validation."""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from axonflow.types import (
    AuditResult,
    AxonFlowConfig,
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


class TestMode:
    """Test Mode enum."""

    def test_production_mode(self) -> None:
        """Test production mode value."""
        assert Mode.PRODUCTION.value == "production"

    def test_sandbox_mode(self) -> None:
        """Test sandbox mode value."""
        assert Mode.SANDBOX.value == "sandbox"

    def test_mode_from_string(self) -> None:
        """Test creating mode from string."""
        assert Mode("production") == Mode.PRODUCTION
        assert Mode("sandbox") == Mode.SANDBOX


class TestRetryConfig:
    """Test RetryConfig model."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = RetryConfig()
        assert config.enabled is True
        assert config.max_attempts == 3
        assert config.initial_delay == 1.0
        assert config.max_delay == 30.0
        assert config.exponential_base == 2.0

    def test_custom_values(self) -> None:
        """Test custom configuration values."""
        config = RetryConfig(
            enabled=False,
            max_attempts=5,
            initial_delay=2.0,
            max_delay=60.0,
            exponential_base=3.0,
        )
        assert config.enabled is False
        assert config.max_attempts == 5

    def test_validation_max_attempts(self) -> None:
        """Test max_attempts validation."""
        with pytest.raises(ValidationError):
            RetryConfig(max_attempts=0)  # min is 1

        with pytest.raises(ValidationError):
            RetryConfig(max_attempts=11)  # max is 10

    def test_frozen(self) -> None:
        """Test config is immutable."""
        config = RetryConfig()
        with pytest.raises(ValidationError):
            config.enabled = False  # type: ignore[misc]


class TestCacheConfig:
    """Test CacheConfig model."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = CacheConfig()
        assert config.enabled is True
        assert config.ttl == 60.0
        assert config.max_size == 1000

    def test_validation_ttl(self) -> None:
        """Test TTL must be positive."""
        with pytest.raises(ValidationError):
            CacheConfig(ttl=0)

        with pytest.raises(ValidationError):
            CacheConfig(ttl=-1)


class TestAxonFlowConfig:
    """Test AxonFlowConfig model."""

    def test_required_fields(self) -> None:
        """Test required fields validation."""
        with pytest.raises(ValidationError):
            AxonFlowConfig()  # type: ignore[call-arg]

    def test_minimal_config(self) -> None:
        """Test minimal configuration."""
        config = AxonFlowConfig(
            agent_url="https://test.com",
            client_id="client",
            client_secret="secret",
        )
        assert config.agent_url == "https://test.com"
        assert config.mode == Mode.PRODUCTION
        assert config.debug is False

    def test_full_config(self) -> None:
        """Test full configuration."""
        config = AxonFlowConfig(
            agent_url="https://test.com",
            client_id="client",
            client_secret="secret",
            license_key="license-123",
            mode=Mode.SANDBOX,
            debug=True,
            timeout=30.0,
            insecure_skip_verify=True,
        )
        assert config.license_key == "license-123"
        assert config.mode == Mode.SANDBOX
        assert config.timeout == 30.0

    def test_empty_url_validation(self) -> None:
        """Test empty URL validation."""
        with pytest.raises(ValidationError):
            AxonFlowConfig(
                agent_url="",
                client_id="client",
                client_secret="secret",
            )


class TestClientRequest:
    """Test ClientRequest model."""

    def test_create_request(self) -> None:
        """Test creating a client request."""
        request = ClientRequest(
            query="What is AI?",
            user_token="token-123",
            client_id="client",
            request_type="chat",
        )
        assert request.query == "What is AI?"
        assert request.context == {}

    def test_request_with_context(self) -> None:
        """Test request with context."""
        request = ClientRequest(
            query="Query",
            user_token="token",
            client_id="client",
            request_type="sql",
            context={"database": "postgres"},
        )
        assert request.context["database"] == "postgres"


class TestClientResponse:
    """Test ClientResponse model."""

    def test_successful_response(self) -> None:
        """Test successful response."""
        response = ClientResponse(
            success=True,
            data={"result": "test"},
        )
        assert response.success is True
        assert response.blocked is False
        assert response.data == {"result": "test"}

    def test_blocked_response(self) -> None:
        """Test blocked response."""
        response = ClientResponse(
            success=False,
            blocked=True,
            block_reason="Policy violation",
        )
        assert response.success is False
        assert response.blocked is True
        assert response.block_reason == "Policy violation"

    def test_response_with_policy_info(self) -> None:
        """Test response with policy evaluation info."""
        response = ClientResponse(
            success=True,
            policy_info=PolicyEvaluationInfo(
                policies_evaluated=["policy1", "policy2"],
                processing_time="10ms",
            ),
        )
        assert response.policy_info is not None
        assert len(response.policy_info.policies_evaluated) == 2


class TestConnectorTypes:
    """Test connector-related types."""

    def test_connector_metadata(self) -> None:
        """Test ConnectorMetadata model."""
        metadata = ConnectorMetadata(
            id="postgres",
            name="PostgreSQL",
            type="database",
            version="1.0.0",
        )
        assert metadata.id == "postgres"
        assert metadata.installed is False

    def test_connector_install_request(self) -> None:
        """Test ConnectorInstallRequest model."""
        request = ConnectorInstallRequest(
            connector_id="postgres",
            name="My DB",
            tenant_id="tenant-123",
            credentials={"password": "secret"},
        )
        assert request.credentials["password"] == "secret"

    def test_connector_response(self) -> None:
        """Test ConnectorResponse model."""
        response = ConnectorResponse(
            success=True,
            data={"rows": []},
        )
        assert response.success is True


class TestPlanTypes:
    """Test planning-related types."""

    def test_plan_step(self) -> None:
        """Test PlanStep model."""
        step = PlanStep(
            id="step-1",
            name="Fetch data",
            type="data",
            depends_on=["step-0"],
        )
        assert step.id == "step-1"
        assert "step-0" in step.depends_on

    def test_plan_response(self) -> None:
        """Test PlanResponse model."""
        plan = PlanResponse(
            plan_id="plan-123",
            steps=[
                PlanStep(id="s1", name="Step 1", type="data"),
                PlanStep(id="s2", name="Step 2", type="process"),
            ],
            domain="travel",
        )
        assert plan.plan_id == "plan-123"
        assert len(plan.steps) == 2
        assert plan.domain == "travel"

    def test_plan_execution_response(self) -> None:
        """Test PlanExecutionResponse model."""
        result = PlanExecutionResponse(
            plan_id="plan-123",
            status="completed",
            result="Success",
            duration="5.2s",
        )
        assert result.status == "completed"


class TestGatewayTypes:
    """Test Gateway Mode types."""

    def test_rate_limit_info(self) -> None:
        """Test RateLimitInfo model."""
        info = RateLimitInfo(
            limit=100,
            remaining=50,
            reset_at=datetime.fromisoformat("2025-12-04T12:00:00"),
        )
        assert info.limit == 100
        assert info.remaining == 50

    def test_policy_approval_result(self) -> None:
        """Test PolicyApprovalResult model."""
        result = PolicyApprovalResult(
            context_id="ctx-123",
            approved=True,
            expires_at=datetime.fromisoformat("2025-12-04T13:00:00"),
        )
        assert result.context_id == "ctx-123"
        assert result.approved is True
        assert result.approved_data == {}

    def test_token_usage(self) -> None:
        """Test TokenUsage model."""
        usage = TokenUsage(
            prompt_tokens=100,
            completion_tokens=50,
            total_tokens=150,
        )
        assert usage.total_tokens == 150

    def test_token_usage_validation(self) -> None:
        """Test TokenUsage validation."""
        with pytest.raises(ValidationError):
            TokenUsage(
                prompt_tokens=-1,
                completion_tokens=0,
                total_tokens=0,
            )

    def test_audit_result(self) -> None:
        """Test AuditResult model."""
        result = AuditResult(
            success=True,
            audit_id="audit-456",
        )
        assert result.success is True
        assert result.audit_id == "audit-456"
