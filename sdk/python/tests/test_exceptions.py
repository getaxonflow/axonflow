"""Tests for exception classes."""

from __future__ import annotations

import pytest

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


class TestAxonFlowError:
    """Test base AxonFlowError class."""

    def test_basic_error(self) -> None:
        """Test basic error creation."""
        error = AxonFlowError("Something went wrong")
        assert str(error) == "Something went wrong"
        assert error.message == "Something went wrong"
        assert error.details == {}

    def test_error_with_details(self) -> None:
        """Test error with details."""
        error = AxonFlowError(
            "Error occurred",
            details={"code": "ERR001", "context": "testing"},
        )
        assert error.details["code"] == "ERR001"
        assert error.details["context"] == "testing"

    def test_error_is_exception(self) -> None:
        """Test error inherits from Exception."""
        error = AxonFlowError("Test")
        assert isinstance(error, Exception)

    def test_error_can_be_raised(self) -> None:
        """Test error can be raised and caught."""
        with pytest.raises(AxonFlowError) as exc_info:
            raise AxonFlowError("Test error")
        assert "Test error" in str(exc_info.value)


class TestConfigurationError:
    """Test ConfigurationError class."""

    def test_configuration_error(self) -> None:
        """Test configuration error."""
        error = ConfigurationError("Invalid config")
        assert isinstance(error, AxonFlowError)
        assert error.message == "Invalid config"


class TestAuthenticationError:
    """Test AuthenticationError class."""

    def test_authentication_error(self) -> None:
        """Test authentication error."""
        error = AuthenticationError("Invalid credentials")
        assert isinstance(error, AxonFlowError)
        assert error.message == "Invalid credentials"


class TestPolicyViolationError:
    """Test PolicyViolationError class."""

    def test_basic_policy_error(self) -> None:
        """Test basic policy violation error."""
        error = PolicyViolationError("Request blocked")
        assert error.message == "Request blocked"
        assert error.policy is None
        assert error.block_reason is None

    def test_policy_error_with_details(self) -> None:
        """Test policy error with full details."""
        error = PolicyViolationError(
            "Request blocked by policy",
            policy="rate-limit",
            block_reason="Too many requests",
        )
        assert error.policy == "rate-limit"
        assert error.block_reason == "Too many requests"
        assert error.details["policy"] == "rate-limit"

    def test_policy_error_inheritance(self) -> None:
        """Test policy error inherits from AxonFlowError."""
        error = PolicyViolationError("Test")
        assert isinstance(error, AxonFlowError)


class TestRateLimitError:
    """Test RateLimitError class."""

    def test_rate_limit_error(self) -> None:
        """Test rate limit error."""
        error = RateLimitError(
            "Rate limit exceeded",
            limit=100,
            remaining=0,
            reset_at="2025-12-04T13:00:00Z",
        )
        assert error.limit == 100
        assert error.remaining == 0
        assert error.reset_at == "2025-12-04T13:00:00Z"

    def test_rate_limit_details(self) -> None:
        """Test rate limit error details."""
        error = RateLimitError("Exceeded", limit=50, remaining=0)
        assert error.details["limit"] == 50
        assert error.details["remaining"] == 0


class TestConnectionError:
    """Test ConnectionError class."""

    def test_connection_error(self) -> None:
        """Test connection error."""
        error = ConnectionError("Failed to connect")
        assert isinstance(error, AxonFlowError)
        assert error.message == "Failed to connect"


class TestTimeoutError:
    """Test TimeoutError class."""

    def test_timeout_error(self) -> None:
        """Test timeout error."""
        error = TimeoutError("Request timed out after 30s")
        assert isinstance(error, AxonFlowError)
        assert "30s" in error.message


class TestConnectorError:
    """Test ConnectorError class."""

    def test_basic_connector_error(self) -> None:
        """Test basic connector error."""
        error = ConnectorError("Connector failed")
        assert error.connector is None
        assert error.operation is None

    def test_connector_error_with_details(self) -> None:
        """Test connector error with details."""
        error = ConnectorError(
            "Query failed",
            connector="postgres",
            operation="SELECT",
        )
        assert error.connector == "postgres"
        assert error.operation == "SELECT"
        assert error.details["connector"] == "postgres"


class TestPlanExecutionError:
    """Test PlanExecutionError class."""

    def test_basic_plan_error(self) -> None:
        """Test basic plan execution error."""
        error = PlanExecutionError("Plan failed")
        assert error.plan_id is None
        assert error.step is None

    def test_plan_error_with_details(self) -> None:
        """Test plan error with details."""
        error = PlanExecutionError(
            "Step failed",
            plan_id="plan-123",
            step="step-2",
        )
        assert error.plan_id == "plan-123"
        assert error.step == "step-2"
        assert error.details["plan_id"] == "plan-123"


class TestExceptionHierarchy:
    """Test exception hierarchy and catching."""

    def test_catch_all_axonflow_errors(self) -> None:
        """Test all errors can be caught as AxonFlowError."""
        errors = [
            ConfigurationError("config"),
            AuthenticationError("auth"),
            PolicyViolationError("policy"),
            RateLimitError("rate", limit=100, remaining=0),
            ConnectionError("connection"),
            TimeoutError("timeout"),
            ConnectorError("connector"),
            PlanExecutionError("plan"),
        ]

        for error in errors:
            with pytest.raises(AxonFlowError):
                raise error

    def test_specific_catch(self) -> None:
        """Test specific exception types can be caught."""
        with pytest.raises(PolicyViolationError):
            raise PolicyViolationError("Test")

        # Should not catch other types
        with pytest.raises(AuthenticationError):
            try:
                raise AuthenticationError("Auth failed")
            except PolicyViolationError:
                pytest.fail("Should not catch PolicyViolationError")
            except AuthenticationError:
                raise
