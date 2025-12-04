"""Tests for Gateway Mode functionality."""

from __future__ import annotations

from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from axonflow import AxonFlow, TokenUsage


class TestGatewayPreCheck:
    """Test Gateway Mode pre-check functionality."""

    @pytest.mark.asyncio
    async def test_pre_check_approved(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_pre_check_response: dict[str, Any],
    ) -> None:
        """Test successful pre-check approval."""
        httpx_mock.add_response(json=mock_pre_check_response)

        result = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Find patients with diabetes",
            data_sources=["postgres"],
        )

        assert result.approved is True
        assert result.context_id == "ctx-123"
        assert "patients" in result.approved_data
        assert "hipaa" in result.policies

    @pytest.mark.asyncio
    async def test_pre_check_with_rate_limit(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_pre_check_response: dict[str, Any],
    ) -> None:
        """Test pre-check with rate limit info."""
        httpx_mock.add_response(json=mock_pre_check_response)

        result = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Find patients",
        )

        assert result.rate_limit_info is not None
        assert result.rate_limit_info.limit == 100
        assert result.rate_limit_info.remaining == 99

    @pytest.mark.asyncio
    async def test_pre_check_blocked(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test pre-check when blocked."""
        httpx_mock.add_response(
            json={
                "context_id": "ctx-blocked",
                "approved": False,
                "approved_data": {},
                "policies": ["hipaa"],
                "expires_at": "2025-12-04T13:00:00Z",
                "block_reason": "Sensitive patient data access requires approval",
            }
        )

        result = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Show all SSN numbers",
        )

        assert result.approved is False
        assert result.block_reason is not None
        assert "approval" in result.block_reason.lower()

    @pytest.mark.asyncio
    async def test_pre_check_with_context(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_pre_check_response: dict[str, Any],
    ) -> None:
        """Test pre-check with additional context."""
        httpx_mock.add_response(json=mock_pre_check_response)

        result = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Find patients",
            data_sources=["postgres", "salesforce"],
            context={"department": "cardiology", "urgency": "high"},
        )

        request = httpx_mock.get_requests()[0]
        assert request is not None
        assert "/api/policy/pre-check" in str(request.url)

    @pytest.mark.asyncio
    async def test_pre_check_no_rate_limit(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Test pre-check without rate limit info."""
        httpx_mock.add_response(
            json={
                "context_id": "ctx-123",
                "approved": True,
                "approved_data": {},
                "policies": [],
                "expires_at": "2025-12-04T13:00:00Z",
            }
        )

        result = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Simple query",
        )

        assert result.rate_limit_info is None


class TestGatewayAudit:
    """Test Gateway Mode audit functionality."""

    @pytest.mark.asyncio
    async def test_audit_llm_call(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_audit_response: dict[str, Any],
    ) -> None:
        """Test successful audit logging."""
        httpx_mock.add_response(json=mock_audit_response)

        result = await client.audit_llm_call(
            context_id="ctx-123",
            response_summary="Found 5 patients with recent lab results",
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
            ),
            latency_ms=250,
        )

        assert result.success is True
        assert result.audit_id == "audit-456"

    @pytest.mark.asyncio
    async def test_audit_with_metadata(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_audit_response: dict[str, Any],
    ) -> None:
        """Test audit with additional metadata."""
        httpx_mock.add_response(json=mock_audit_response)

        result = await client.audit_llm_call(
            context_id="ctx-123",
            response_summary="Generated summary",
            provider="anthropic",
            model="claude-3-sonnet",
            token_usage=TokenUsage(
                prompt_tokens=200,
                completion_tokens=100,
                total_tokens=300,
            ),
            latency_ms=500,
            metadata={
                "session_id": "session-123",
                "request_id": "req-456",
                "user_feedback": "helpful",
            },
        )

        assert result.success is True

    @pytest.mark.asyncio
    async def test_audit_request_body(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_audit_response: dict[str, Any],
    ) -> None:
        """Test audit request body format."""
        httpx_mock.add_response(json=mock_audit_response)

        await client.audit_llm_call(
            context_id="ctx-789",
            response_summary="Test summary",
            provider="bedrock",
            model="claude-v2",
            token_usage=TokenUsage(
                prompt_tokens=50,
                completion_tokens=25,
                total_tokens=75,
            ),
            latency_ms=150,
        )

        request = httpx_mock.get_requests()[0]
        assert "/api/audit/llm-call" in str(request.url)


class TestGatewayModeFlow:
    """Test complete Gateway Mode flow."""

    @pytest.mark.asyncio
    async def test_complete_gateway_flow(
        self,
        client: AxonFlow,
        httpx_mock: HTTPXMock,
        mock_pre_check_response: dict[str, Any],
        mock_audit_response: dict[str, Any],
    ) -> None:
        """Test complete pre-check -> LLM call -> audit flow."""
        # Mock pre-check
        httpx_mock.add_response(json=mock_pre_check_response)
        # Mock audit
        httpx_mock.add_response(json=mock_audit_response)

        # Step 1: Pre-check
        ctx = await client.get_policy_approved_context(
            user_token="user-jwt",
            query="Find patients with diabetes",
            data_sources=["postgres"],
        )

        assert ctx.approved is True
        context_id = ctx.context_id

        # Step 2: (Simulated) LLM call would happen here
        # ...

        # Step 3: Audit
        audit_result = await client.audit_llm_call(
            context_id=context_id,
            response_summary="Found 5 patients",
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=100,
                completion_tokens=50,
                total_tokens=150,
            ),
            latency_ms=250,
        )

        assert audit_result.success is True
        assert len(httpx_mock.get_requests()) == 2


class TestSyncGatewayMode:
    """Test Gateway Mode with sync client."""

    def test_sync_pre_check(
        self,
        sync_client,
        httpx_mock: HTTPXMock,
        mock_pre_check_response: dict[str, Any],
    ) -> None:
        """Test sync pre-check."""
        httpx_mock.add_response(json=mock_pre_check_response)

        result = sync_client.get_policy_approved_context(
            user_token="user-jwt",
            query="Test query",
        )

        assert result.approved is True

    def test_sync_audit(
        self,
        sync_client,
        httpx_mock: HTTPXMock,
        mock_audit_response: dict[str, Any],
    ) -> None:
        """Test sync audit."""
        httpx_mock.add_response(json=mock_audit_response)

        result = sync_client.audit_llm_call(
            context_id="ctx-123",
            response_summary="Test",
            provider="openai",
            model="gpt-4",
            token_usage=TokenUsage(
                prompt_tokens=10,
                completion_tokens=5,
                total_tokens=15,
            ),
            latency_ms=100,
        )

        assert result.success is True
