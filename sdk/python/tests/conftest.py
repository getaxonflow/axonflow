"""Pytest fixtures for AxonFlow SDK tests."""

from __future__ import annotations

from typing import Any, AsyncGenerator

import pytest
import pytest_asyncio
from pytest_httpx import HTTPXMock

from axonflow import AxonFlow


@pytest.fixture
def config_dict() -> dict[str, Any]:
    """Base configuration dictionary."""
    return {
        "agent_url": "https://test.axonflow.com",
        "client_id": "test-client",
        "client_secret": "test-secret",
        "debug": True,
    }


@pytest_asyncio.fixture
async def client(config_dict: dict[str, Any]) -> AsyncGenerator[AxonFlow, None]:
    """Create test AxonFlow client."""
    async with AxonFlow(**config_dict) as c:
        yield c


@pytest.fixture
def sync_client(config_dict: dict[str, Any]):
    """Create sync test AxonFlow client."""
    with AxonFlow.sync(**config_dict) as c:
        yield c


@pytest.fixture
def mock_health_response() -> dict[str, Any]:
    """Mock health check response."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "components": {
            "database": "connected",
            "orchestrator": "reachable",
        },
    }


@pytest.fixture
def mock_query_response() -> dict[str, Any]:
    """Mock successful query response."""
    return {
        "success": True,
        "data": {"result": "test result"},
        "blocked": False,
        "metadata": {},
        "policy_info": {
            "policies_evaluated": ["default"],
            "static_checks": [],
            "processing_time": "5ms",
            "tenant_id": "test",
        },
    }


@pytest.fixture
def mock_blocked_response() -> dict[str, Any]:
    """Mock blocked query response."""
    return {
        "success": False,
        "blocked": True,
        "block_reason": "Rate limit exceeded",
        "error": "Request blocked by policy",
    }


@pytest.fixture
def mock_connector_list() -> list[dict[str, Any]]:
    """Mock connector list response."""
    return [
        {
            "id": "postgres",
            "name": "PostgreSQL",
            "type": "database",
            "version": "1.0.0",
            "description": "PostgreSQL database connector",
            "category": "database",
            "tags": ["sql", "relational"],
            "capabilities": ["read", "write"],
            "config_schema": {},
            "installed": True,
            "healthy": True,
        },
        {
            "id": "salesforce",
            "name": "Salesforce",
            "type": "crm",
            "version": "1.0.0",
            "description": "Salesforce CRM connector",
            "category": "crm",
            "tags": ["crm", "sales"],
            "capabilities": ["read"],
            "config_schema": {},
            "installed": False,
            "healthy": False,
        },
    ]


@pytest.fixture
def mock_plan_response() -> dict[str, Any]:
    """Mock plan generation response."""
    return {
        "success": True,
        "plan_id": "plan-123",
        "data": {
            "steps": [
                {
                    "id": "step-1",
                    "name": "Fetch data",
                    "type": "data",
                    "description": "Fetch customer data",
                    "depends_on": [],
                    "agent": "data-agent",
                    "parameters": {},
                },
                {
                    "id": "step-2",
                    "name": "Process data",
                    "type": "process",
                    "description": "Process the data",
                    "depends_on": ["step-1"],
                    "agent": "process-agent",
                    "parameters": {},
                },
            ],
            "domain": "generic",
            "complexity": 2,
            "parallel": False,
        },
        "metadata": {},
    }


@pytest.fixture
def mock_pre_check_response() -> dict[str, Any]:
    """Mock Gateway Mode pre-check response."""
    return {
        "context_id": "ctx-123",
        "approved": True,
        "approved_data": {"patients": ["patient-1", "patient-2"]},
        "policies": ["hipaa", "gdpr"],
        "rate_limit": {
            "limit": 100,
            "remaining": 99,
            "reset_at": "2025-12-05T00:00:00Z",
        },
        "expires_at": "2025-12-04T13:00:00Z",
        "block_reason": None,
    }


@pytest.fixture
def mock_audit_response() -> dict[str, Any]:
    """Mock Gateway Mode audit response."""
    return {
        "success": True,
        "audit_id": "audit-456",
    }
