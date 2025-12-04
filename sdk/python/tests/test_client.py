"""Unit tests for AxonFlow client."""

from __future__ import annotations

from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from axonflow import AxonFlow, Mode
from axonflow.exceptions import (
    AuthenticationError,
    AxonFlowError,
    PolicyViolationError,
)


class TestClientInitialization:
    """Test client initialization."""

    def test_creates_with_required_params(self, config_dict: dict[str, Any]) -> None:
        """Test client creates with required parameters."""
        client = AxonFlow(**config_dict)
        assert client.config.agent_url == config_dict["agent_url"]
        assert client.config.client_id == config_dict["client_id"]

    def test_default_values_applied(self, config_dict: dict[str, Any]) -> None:
        """Test default configuration values."""
        client = AxonFlow(**config_dict)
        assert client.config.timeout == 60.0
        assert client.config.retry.enabled is True
        assert client.config.retry.max_attempts == 3

    def test_sandbox_mode(self) -> None:
        """Test sandbox client creation."""
        client = AxonFlow.sandbox()
        assert "staging" in client.config.agent_url
        assert client.config.debug is True
        assert client.config.mode == Mode.SANDBOX

    def test_mode_string_conversion(self, config_dict: dict[str, Any]) -> None:
        """Test mode string is converted to enum."""
        client = AxonFlow(**config_dict, mode="sandbox")
        assert client.config.mode == Mode.SANDBOX

    def test_url_trailing_slash_stripped(self) -> None:
        """Test trailing slash is stripped from URL."""
        client = AxonFlow(
            agent_url="https://test.axonflow.com/",
            client_id="test",
            client_secret="test",
        )
        assert client.config.agent_url == "https://test.axonflow.com"

    def test_license_key_optional(self, config_dict: dict[str, Any]) -> None:
        """Test license key is optional."""
        client = AxonFlow(**config_dict)
        assert client.config.license_key is None

        client_with_license = AxonFlow(**config_dict, license_key="license-123")
        assert client_with_license.config.license_key == "license-123"


class TestHealthCheck:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check_success(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_health_response: dict[str, Any],
    ) -> None:
        """Test successful health check."""
        httpx_mock.add_response(json=mock_health_response)
        result = await client.health_check()
        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_failure(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test health check returns False on error."""
        httpx_mock.add_response(status_code=500)
        result = await client.health_check()
        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_unhealthy(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test health check returns False when unhealthy."""
        httpx_mock.add_response(json={"status": "unhealthy"})
        result = await client.health_check()
        assert result is False


class TestExecuteQuery:
    """Test query execution."""

    @pytest.mark.asyncio
    async def test_successful_query(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test successful query execution."""
        httpx_mock.add_response(json=mock_query_response)

        result = await client.execute_query(
            user_token="test-token",
            query="What is AI?",
            request_type="chat",
        )

        assert result.success is True
        assert result.blocked is False
        assert result.data == {"result": "test result"}

    @pytest.mark.asyncio
    async def test_blocked_by_policy(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_blocked_response: dict[str, Any],
    ) -> None:
        """Test query blocked by policy raises exception."""
        httpx_mock.add_response(json=mock_blocked_response)

        with pytest.raises(PolicyViolationError) as exc_info:
            await client.execute_query(
                user_token="test-token",
                query="What is AI?",
                request_type="chat",
            )

        assert "Rate limit" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_authentication_error(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test authentication error handling."""
        httpx_mock.add_response(status_code=401)

        with pytest.raises(AuthenticationError):
            await client.execute_query(
                user_token="bad-token",
                query="test",
                request_type="chat",
            )

    @pytest.mark.asyncio
    async def test_policy_violation_403(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test 403 response raises PolicyViolationError."""
        httpx_mock.add_response(
            status_code=403,
            json={
                "message": "Access denied",
                "policy": "access-control",
                "block_reason": "Insufficient permissions",
            },
        )

        with pytest.raises(PolicyViolationError) as exc_info:
            await client.execute_query(
                user_token="test",
                query="test",
                request_type="chat",
            )

        assert exc_info.value.policy == "access-control"

    @pytest.mark.asyncio
    async def test_generic_http_error(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test generic HTTP error handling."""
        httpx_mock.add_response(status_code=500, text="Internal Server Error")

        with pytest.raises(AxonFlowError) as exc_info:
            await client.execute_query(
                user_token="test",
                query="test",
                request_type="chat",
            )

        assert "HTTP 500" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_query_with_context(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test query with additional context."""
        httpx_mock.add_response(json=mock_query_response)

        result = await client.execute_query(
            user_token="test-token",
            query="What is AI?",
            request_type="chat",
            context={"session_id": "123", "user_role": "admin"},
        )

        assert result.success is True


class TestCaching:
    """Test response caching."""

    @pytest.mark.asyncio
    async def test_cache_hit(
        self,
        config_dict: dict[str, Any],
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test cache returns same response."""
        httpx_mock.add_response(json=mock_query_response)

        async with AxonFlow(**config_dict) as client:
            # First call
            result1 = await client.execute_query(
                user_token="test",
                query="cached query",
                request_type="chat",
            )

            # Second call - should hit cache
            result2 = await client.execute_query(
                user_token="test",
                query="cached query",
                request_type="chat",
            )

            assert result1.data == result2.data
            # Only one HTTP request should have been made
            assert len(httpx_mock.get_requests()) == 1

    @pytest.mark.asyncio
    async def test_cache_miss_different_query(
        self,
        config_dict: dict[str, Any],
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test cache miss for different queries."""
        httpx_mock.add_response(json=mock_query_response)
        httpx_mock.add_response(json=mock_query_response)

        async with AxonFlow(**config_dict) as client:
            await client.execute_query("test", "query1", "chat")
            await client.execute_query("test", "query2", "chat")

            # Two HTTP requests should have been made
            assert len(httpx_mock.get_requests()) == 2

    @pytest.mark.asyncio
    async def test_cache_disabled(
        self,
        config_dict: dict[str, Any],
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test caching can be disabled."""
        httpx_mock.add_response(json=mock_query_response)
        httpx_mock.add_response(json=mock_query_response)

        async with AxonFlow(**config_dict, cache_enabled=False) as client:
            await client.execute_query("test", "query", "chat")
            await client.execute_query("test", "query", "chat")

            # Both requests should be made
            assert len(httpx_mock.get_requests()) == 2


class TestConnectors:
    """Test connector operations."""

    @pytest.mark.asyncio
    async def test_list_connectors(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_connector_list: list[dict[str, Any]],
    ) -> None:
        """Test listing connectors."""
        httpx_mock.add_response(json=mock_connector_list)

        connectors = await client.list_connectors()

        assert len(connectors) == 2
        assert connectors[0].id == "postgres"
        assert connectors[0].installed is True
        assert connectors[1].id == "salesforce"
        assert connectors[1].installed is False

    @pytest.mark.asyncio
    async def test_install_connector(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test installing a connector."""
        from axonflow import ConnectorInstallRequest

        httpx_mock.add_response(status_code=201)

        await client.install_connector(
            ConnectorInstallRequest(
                connector_id="salesforce",
                name="My Salesforce",
                tenant_id="tenant-123",
                options={"api_version": "v55.0"},
                credentials={"api_key": "secret"},
            )
        )

        request = httpx_mock.get_requests()[0]
        assert "/api/connectors/install" in str(request.url)

    @pytest.mark.asyncio
    async def test_query_connector(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test querying a connector."""
        httpx_mock.add_response(
            json={
                "success": True,
                "data": {"rows": [{"id": 1}, {"id": 2}]},
            }
        )

        result = await client.query_connector(
            user_token="test",
            connector_name="postgres",
            operation="query",
            params={"sql": "SELECT * FROM users"},
        )

        assert result.success is True
        assert result.data["rows"][0]["id"] == 1


class TestPlanning:
    """Test multi-agent planning."""

    @pytest.mark.asyncio
    async def test_generate_plan(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_plan_response: dict[str, Any],
    ) -> None:
        """Test plan generation."""
        httpx_mock.add_response(json=mock_plan_response)

        plan = await client.generate_plan(
            query="Book a flight and hotel for my trip",
            domain="travel",
        )

        assert plan.plan_id == "plan-123"
        assert len(plan.steps) == 2
        assert plan.steps[0].name == "Fetch data"
        assert plan.steps[1].depends_on == ["step-1"]

    @pytest.mark.asyncio
    async def test_execute_plan(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test plan execution."""
        httpx_mock.add_response(
            json={
                "success": True,
                "result": "Trip booked successfully",
                "metadata": {
                    "duration": "5.2s",
                    "step_results": {"step-1": "done", "step-2": "done"},
                },
            }
        )

        result = await client.execute_plan("plan-123")

        assert result.status == "completed"
        assert result.result == "Trip booked successfully"

    @pytest.mark.asyncio
    async def test_get_plan_status(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test getting plan status."""
        httpx_mock.add_response(
            json={
                "plan_id": "plan-123",
                "status": "running",
                "step_results": {"step-1": "done"},
            }
        )

        result = await client.get_plan_status("plan-123")

        assert result.status == "running"


class TestSyncClient:
    """Test synchronous client wrapper."""

    def test_sync_health_check(
        self,
        sync_client,
        httpx_mock: HTTPXMock,
        mock_health_response: dict[str, Any],
    ) -> None:
        """Test sync health check."""
        httpx_mock.add_response(json=mock_health_response)
        result = sync_client.health_check()
        assert result is True

    def test_sync_execute_query(
        self,
        sync_client,
        httpx_mock: HTTPXMock,
        mock_query_response: dict[str, Any],
    ) -> None:
        """Test sync query execution."""
        httpx_mock.add_response(json=mock_query_response)
        result = sync_client.execute_query("test", "query", "chat")
        assert result.success is True

    def test_sync_context_manager(
        self,
        config_dict: dict[str, Any],
        httpx_mock: HTTPXMock,
        mock_health_response: dict[str, Any],
    ) -> None:
        """Test sync context manager."""
        httpx_mock.add_response(json=mock_health_response)

        with AxonFlow.sync(**config_dict) as client:
            result = client.health_check()
            assert result is True


class TestContextManager:
    """Test async context manager."""

    @pytest.mark.asyncio
    async def test_async_context_manager(
        self,
        config_dict: dict[str, Any],
        httpx_mock: HTTPXMock,
        mock_health_response: dict[str, Any],
    ) -> None:
        """Test async context manager."""
        httpx_mock.add_response(json=mock_health_response)

        async with AxonFlow(**config_dict) as client:
            result = await client.health_check()
            assert result is True

    @pytest.mark.asyncio
    async def test_explicit_close(
        self,
        config_dict: dict[str, Any],
    ) -> None:
        """Test explicit close."""
        client = AxonFlow(**config_dict)
        await client.close()
        # No exception should be raised
