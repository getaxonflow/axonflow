"""AxonFlow SDK Main Client.

The primary interface for interacting with AxonFlow governance platform.
Supports both async and sync usage patterns.

Example:
    >>> from axonflow import AxonFlow
    >>>
    >>> # Async usage
    >>> async with AxonFlow(agent_url="...", client_id="...", client_secret="...") as client:
    ...     result = await client.execute_query("user-token", "What is AI?", "chat")
    ...     print(result.data)
    >>>
    >>> # Sync usage
    >>> client = AxonFlow.sync(agent_url="...", client_id="...", client_secret="...")
    >>> result = client.execute_query("user-token", "What is AI?", "chat")
"""

from __future__ import annotations

import asyncio
import hashlib
from datetime import datetime
from typing import TYPE_CHECKING, Any

import httpx
import structlog
from cachetools import TTLCache
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from axonflow.exceptions import (
    AuthenticationError,
    AxonFlowError,
    ConnectionError,
    PolicyViolationError,
    TimeoutError,
)
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
    RateLimitInfo,
    RetryConfig,
    TokenUsage,
)

if TYPE_CHECKING:
    from types import TracebackType

logger = structlog.get_logger(__name__)


class AxonFlow:
    """Main AxonFlow client for AI governance.

    This client provides async-first API for interacting with AxonFlow Agent.
    All methods are async by default, with sync wrappers available via `.sync()`.

    Attributes:
        config: Client configuration
    """

    __slots__ = ("_config", "_http_client", "_cache", "_logger")

    def __init__(
        self,
        agent_url: str,
        client_id: str,
        client_secret: str,
        *,
        license_key: str | None = None,
        mode: Mode | str = Mode.PRODUCTION,
        debug: bool = False,
        timeout: float = 60.0,
        insecure_skip_verify: bool = False,
        retry_config: RetryConfig | None = None,
        cache_enabled: bool = True,
        cache_ttl: float = 60.0,
        cache_max_size: int = 1000,
    ) -> None:
        """Initialize AxonFlow client.

        Args:
            agent_url: AxonFlow Agent URL
            client_id: Client ID for authentication
            client_secret: Client secret for authentication
            license_key: Optional license key for organization-level auth
            mode: Operation mode (production or sandbox)
            debug: Enable debug logging
            timeout: Request timeout in seconds
            insecure_skip_verify: Skip TLS verification (dev only)
            retry_config: Retry configuration
            cache_enabled: Enable response caching
            cache_ttl: Cache TTL in seconds
            cache_max_size: Maximum cache entries
        """
        if isinstance(mode, str):
            mode = Mode(mode)

        self._config = AxonFlowConfig(
            agent_url=agent_url.rstrip("/"),
            client_id=client_id,
            client_secret=client_secret,
            license_key=license_key,
            mode=mode,
            debug=debug,
            timeout=timeout,
            insecure_skip_verify=insecure_skip_verify,
            retry=retry_config or RetryConfig(),
            cache=CacheConfig(enabled=cache_enabled, ttl=cache_ttl, max_size=cache_max_size),
        )

        # Configure SSL verification
        verify_ssl: bool = not insecure_skip_verify

        # Build headers
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Client-Secret": client_secret,
        }
        if license_key:
            headers["X-License-Key"] = license_key

        # Initialize HTTP client
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            verify=verify_ssl,
            headers=headers,
        )

        # Initialize cache
        self._cache: TTLCache[str, ClientResponse] | None = None
        if cache_enabled:
            self._cache = TTLCache(maxsize=cache_max_size, ttl=cache_ttl)

        # Initialize logger
        self._logger = structlog.get_logger(__name__).bind(
            client_id=client_id,
            mode=mode.value,
        )

        if debug:
            self._logger.info(
                "AxonFlow client initialized",
                agent_url=agent_url,
            )

    @property
    def config(self) -> AxonFlowConfig:
        """Get client configuration."""
        return self._config

    async def __aenter__(self) -> AxonFlow:
        """Async context manager entry."""
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.close()

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http_client.aclose()

    @classmethod
    def sync(
        cls,
        agent_url: str,
        client_id: str,
        client_secret: str,
        **kwargs: Any,
    ) -> SyncAxonFlow:
        """Create a synchronous client wrapper.

        Example:
            >>> client = AxonFlow.sync(agent_url="...", client_id="...", client_secret="...")
            >>> result = client.execute_query("token", "query", "chat")
        """
        return SyncAxonFlow(cls(agent_url, client_id, client_secret, **kwargs))

    @classmethod
    def sandbox(cls, api_key: str = "demo-key") -> AxonFlow:
        """Create a sandbox client for testing.

        Args:
            api_key: Optional API key (defaults to demo-key)

        Returns:
            Configured AxonFlow client for sandbox environment
        """
        return cls(
            agent_url="https://staging-eu.getaxonflow.com",
            client_id=api_key,
            client_secret=api_key,
            mode=Mode.SANDBOX,
            debug=True,
        )

    def _get_cache_key(self, request_type: str, query: str, user_token: str) -> str:
        """Generate cache key for a request."""
        key = f"{request_type}:{query}:{user_token}"
        return hashlib.sha256(key.encode()).hexdigest()[:32]

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make HTTP request to Agent."""
        url = f"{self._config.agent_url}{path}"

        try:
            if self._config.retry.enabled:
                response = await self._request_with_retry(method, url, json_data)
            else:
                response = await self._http_client.request(method, url, json=json_data)

            response.raise_for_status()
            return response.json()  # type: ignore[no-any-return]

        except httpx.ConnectError as e:
            msg = f"Failed to connect to AxonFlow Agent: {e}"
            raise ConnectionError(msg) from e
        except httpx.TimeoutException as e:
            msg = f"Request timed out: {e}"
            raise TimeoutError(msg) from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:  # noqa: PLR2004
                msg = "Invalid credentials"
                raise AuthenticationError(msg) from e
            if e.response.status_code == 403:  # noqa: PLR2004
                body = e.response.json()
                raise PolicyViolationError(
                    body.get("message", "Request blocked by policy"),
                    policy=body.get("policy"),
                    block_reason=body.get("block_reason"),
                ) from e
            msg = f"HTTP {e.response.status_code}: {e.response.text}"
            raise AxonFlowError(msg) from e

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        json_data: dict[str, Any] | None,
    ) -> httpx.Response:
        """Make request with retry logic."""

        @retry(
            stop=stop_after_attempt(self._config.retry.max_attempts),
            wait=wait_exponential(
                multiplier=self._config.retry.initial_delay,
                max=self._config.retry.max_delay,
                exp_base=self._config.retry.exponential_base,
            ),
            retry=retry_if_exception_type((httpx.ConnectError, httpx.TimeoutException)),
            reraise=True,
        )
        async def _do_request() -> httpx.Response:
            return await self._http_client.request(method, url, json=json_data)

        return await _do_request()

    async def health_check(self) -> bool:
        """Check if AxonFlow Agent is healthy.

        Returns:
            True if agent is healthy, False otherwise
        """
        try:
            response = await self._request("GET", "/health")
            return response.get("status") == "healthy"
        except AxonFlowError:
            return False

    async def execute_query(
        self,
        user_token: str,
        query: str,
        request_type: str,
        context: dict[str, Any] | None = None,
    ) -> ClientResponse:
        """Execute a query through AxonFlow with policy enforcement.

        Args:
            user_token: User authentication token
            query: The query or prompt
            request_type: Type of request (chat, sql, mcp-query, multi-agent-plan)
            context: Optional additional context

        Returns:
            ClientResponse with results or error

        Raises:
            PolicyViolationError: If request is blocked by policy
            AuthenticationError: If credentials are invalid
            TimeoutError: If request times out
        """
        # Check cache
        if self._cache is not None:
            cache_key = self._get_cache_key(request_type, query, user_token)
            if cache_key in self._cache:
                if self._config.debug:
                    self._logger.debug("Cache hit", query=query[:50])
                return self._cache[cache_key]
        else:
            cache_key = ""

        request = ClientRequest(
            query=query,
            user_token=user_token,
            client_id=self._config.client_id,
            request_type=request_type,
            context=context or {},
        )

        if self._config.debug:
            self._logger.debug(
                "Executing query",
                request_type=request_type,
                query=query[:50] if query else "",
            )

        response_data = await self._request(
            "POST",
            "/api/request",
            json_data=request.model_dump(),
        )

        response = ClientResponse.model_validate(response_data)

        # Check for policy violation
        if response.blocked:
            raise PolicyViolationError(
                response.block_reason or "Request blocked by policy",
                block_reason=response.block_reason,
            )

        # Cache successful responses
        if self._cache is not None and response.success and cache_key:
            self._cache[cache_key] = response

        return response

    async def list_connectors(self) -> list[ConnectorMetadata]:
        """List all available MCP connectors.

        Returns:
            List of connector metadata
        """
        response = await self._request("GET", "/api/connectors")
        return [ConnectorMetadata.model_validate(c) for c in response]

    async def install_connector(self, request: ConnectorInstallRequest) -> None:
        """Install an MCP connector.

        Args:
            request: Connector installation request
        """
        await self._request(
            "POST",
            "/api/connectors/install",
            json_data=request.model_dump(),
        )

        if self._config.debug:
            self._logger.info("Connector installed", name=request.name)

    async def query_connector(
        self,
        user_token: str,
        connector_name: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> ConnectorResponse:
        """Query an MCP connector directly.

        Args:
            user_token: User authentication token
            connector_name: Name of the connector
            operation: Operation to perform
            params: Operation parameters

        Returns:
            ConnectorResponse with results
        """
        request_data: dict[str, Any] = {
            "client_id": self._config.client_id,
            "user_token": user_token,
            "connector": connector_name,
            "operation": operation,
            "parameters": params or {},
        }

        if self._config.license_key:
            request_data["license_key"] = self._config.license_key

        response = await self._request(
            "POST",
            "/mcp/resources/query",
            json_data=request_data,
        )

        return ConnectorResponse.model_validate(response)

    async def generate_plan(
        self,
        query: str,
        domain: str | None = None,
    ) -> PlanResponse:
        """Generate a multi-agent execution plan.

        Args:
            query: Natural language query describing the task
            domain: Optional domain hint (travel, healthcare, etc.)

        Returns:
            PlanResponse with generated plan
        """
        context = {"domain": domain} if domain else {}

        response = await self.execute_query(
            user_token="",
            query=query,
            request_type="multi-agent-plan",
            context=context,
        )

        if not response.success:
            msg = f"Plan generation failed: {response.error}"
            raise AxonFlowError(msg)

        # Extract steps from response data
        steps: list[PlanStep] = []
        if response.data and isinstance(response.data, dict):
            steps_data = response.data.get("steps", [])
            steps = [PlanStep.model_validate(s) for s in steps_data]

        return PlanResponse(
            plan_id=response.plan_id or "",
            steps=steps,
            domain=response.data.get("domain", domain or "generic")
            if response.data and isinstance(response.data, dict)
            else (domain or "generic"),
            complexity=response.data.get("complexity", 0)
            if response.data and isinstance(response.data, dict)
            else 0,
            parallel=response.data.get("parallel", False)
            if response.data and isinstance(response.data, dict)
            else False,
            metadata=response.metadata,
        )

    async def execute_plan(self, plan_id: str) -> PlanExecutionResponse:
        """Execute a previously generated plan.

        Args:
            plan_id: ID of the plan to execute

        Returns:
            PlanExecutionResponse with results
        """
        response = await self.execute_query(
            user_token="",
            query="",
            request_type="execute-plan",
            context={"plan_id": plan_id},
        )

        return PlanExecutionResponse(
            plan_id=plan_id,
            status="completed" if response.success else "failed",
            result=response.result,
            step_results=response.metadata.get("step_results", {}),
            error=response.error,
            duration=response.metadata.get("duration"),
        )

    async def get_plan_status(self, plan_id: str) -> PlanExecutionResponse:
        """Get status of a running or completed plan.

        Args:
            plan_id: ID of the plan

        Returns:
            PlanExecutionResponse with current status
        """
        response = await self._request("GET", f"/api/plans/{plan_id}")
        return PlanExecutionResponse.model_validate(response)

    # =========================================================================
    # Gateway Mode Methods
    # =========================================================================

    async def get_policy_approved_context(
        self,
        user_token: str,
        query: str,
        data_sources: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicyApprovalResult:
        """Perform policy pre-check before making LLM call.

        This is the first step in Gateway Mode. Call this before making your
        LLM call to ensure policy compliance.

        Args:
            user_token: JWT token for the user making the request
            query: The query/prompt that will be sent to the LLM
            data_sources: Optional list of MCP connectors to fetch data from
            context: Optional additional context for policy evaluation

        Returns:
            PolicyApprovalResult with context ID and approved data

        Raises:
            AuthenticationError: If user token is invalid
            ConnectionError: If unable to reach AxonFlow Agent
            TimeoutError: If request times out

        Example:
            >>> result = await client.get_policy_approved_context(
            ...     user_token="user-jwt",
            ...     query="Find patients with diabetes",
            ...     data_sources=["postgres"]
            ... )
            >>> if not result.approved:
            ...     raise PolicyViolationError(result.block_reason)
        """
        request_body = {
            "user_token": user_token,
            "client_id": self._config.client_id,
            "query": query,
            "data_sources": data_sources or [],
            "context": context or {},
        }

        if self._config.debug:
            self._logger.debug(
                "Gateway pre-check request",
                query=query[:50] if query else "",
                data_sources=data_sources,
            )

        response = await self._request(
            "POST",
            "/api/policy/pre-check",
            json_data=request_body,
        )

        if self._config.debug:
            self._logger.debug(
                "Gateway pre-check complete",
                context_id=response.get("context_id"),
                approved=response.get("approved"),
            )

        rate_limit = None
        if response.get("rate_limit"):
            rate_limit = RateLimitInfo(
                limit=response["rate_limit"]["limit"],
                remaining=response["rate_limit"]["remaining"],
                reset_at=datetime.fromisoformat(response["rate_limit"]["reset_at"]),
            )

        return PolicyApprovalResult(
            context_id=response["context_id"],
            approved=response["approved"],
            approved_data=response.get("approved_data", {}),
            policies=response.get("policies", []),
            rate_limit_info=rate_limit,
            expires_at=datetime.fromisoformat(response["expires_at"]),
            block_reason=response.get("block_reason"),
        )

    async def audit_llm_call(
        self,
        context_id: str,
        response_summary: str,
        provider: str,
        model: str,
        token_usage: TokenUsage,
        latency_ms: int,
        metadata: dict[str, Any] | None = None,
    ) -> AuditResult:
        """Report LLM call details for audit logging.

        This is the second step in Gateway Mode. Call this after making your
        LLM call to record it in the audit trail.

        Args:
            context_id: Context ID from get_policy_approved_context()
            response_summary: Brief summary of the LLM response (not full response)
            provider: LLM provider name (openai, anthropic, bedrock, ollama)
            model: Model name (gpt-4, claude-3-sonnet, etc.)
            token_usage: Token counts from the LLM response
            latency_ms: Time taken for the LLM call in milliseconds
            metadata: Optional additional metadata to log

        Returns:
            AuditResult confirming the audit was recorded

        Raises:
            AxonFlowError: If audit recording fails

        Example:
            >>> result = await client.audit_llm_call(
            ...     context_id=ctx.context_id,
            ...     response_summary="Found 5 patients with recent lab results",
            ...     provider="openai",
            ...     model="gpt-4",
            ...     token_usage=TokenUsage(
            ...         prompt_tokens=100,
            ...         completion_tokens=50,
            ...         total_tokens=150
            ...     ),
            ...     latency_ms=250
            ... )
        """
        request_body = {
            "context_id": context_id,
            "client_id": self._config.client_id,
            "response_summary": response_summary,
            "provider": provider,
            "model": model,
            "token_usage": {
                "prompt_tokens": token_usage.prompt_tokens,
                "completion_tokens": token_usage.completion_tokens,
                "total_tokens": token_usage.total_tokens,
            },
            "latency_ms": latency_ms,
            "metadata": metadata or {},
        }

        if self._config.debug:
            self._logger.debug(
                "Gateway audit request",
                context_id=context_id,
                provider=provider,
                model=model,
                tokens=token_usage.total_tokens,
            )

        response = await self._request(
            "POST",
            "/api/audit/llm-call",
            json_data=request_body,
        )

        if self._config.debug:
            self._logger.debug(
                "Gateway audit complete",
                audit_id=response.get("audit_id"),
            )

        return AuditResult(
            success=response["success"],
            audit_id=response["audit_id"],
        )


class SyncAxonFlow:
    """Synchronous wrapper for AxonFlow client.

    Wraps all async methods for synchronous usage.
    """

    __slots__ = ("_async_client", "_loop")

    def __init__(self, async_client: AxonFlow) -> None:
        self._async_client = async_client
        self._loop: asyncio.AbstractEventLoop | None = None

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop

    def __enter__(self) -> SyncAxonFlow:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the client."""
        self._get_loop().run_until_complete(self._async_client.close())

    @property
    def config(self) -> AxonFlowConfig:
        """Get client configuration."""
        return self._async_client.config

    def health_check(self) -> bool:
        """Check if AxonFlow Agent is healthy."""
        return self._get_loop().run_until_complete(self._async_client.health_check())

    def execute_query(
        self,
        user_token: str,
        query: str,
        request_type: str,
        context: dict[str, Any] | None = None,
    ) -> ClientResponse:
        """Execute a query through AxonFlow."""
        return self._get_loop().run_until_complete(
            self._async_client.execute_query(user_token, query, request_type, context)
        )

    def list_connectors(self) -> list[ConnectorMetadata]:
        """List all available MCP connectors."""
        return self._get_loop().run_until_complete(self._async_client.list_connectors())

    def install_connector(self, request: ConnectorInstallRequest) -> None:
        """Install an MCP connector."""
        return self._get_loop().run_until_complete(
            self._async_client.install_connector(request)
        )

    def query_connector(
        self,
        user_token: str,
        connector_name: str,
        operation: str,
        params: dict[str, Any] | None = None,
    ) -> ConnectorResponse:
        """Query an MCP connector directly."""
        return self._get_loop().run_until_complete(
            self._async_client.query_connector(user_token, connector_name, operation, params)
        )

    def generate_plan(
        self,
        query: str,
        domain: str | None = None,
    ) -> PlanResponse:
        """Generate a multi-agent execution plan."""
        return self._get_loop().run_until_complete(
            self._async_client.generate_plan(query, domain)
        )

    def execute_plan(self, plan_id: str) -> PlanExecutionResponse:
        """Execute a previously generated plan."""
        return self._get_loop().run_until_complete(self._async_client.execute_plan(plan_id))

    def get_plan_status(self, plan_id: str) -> PlanExecutionResponse:
        """Get status of a running or completed plan."""
        return self._get_loop().run_until_complete(self._async_client.get_plan_status(plan_id))

    # Gateway Mode sync wrappers

    def get_policy_approved_context(
        self,
        user_token: str,
        query: str,
        data_sources: list[str] | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicyApprovalResult:
        """Perform policy pre-check before making LLM call."""
        return self._get_loop().run_until_complete(
            self._async_client.get_policy_approved_context(
                user_token, query, data_sources, context
            )
        )

    def audit_llm_call(
        self,
        context_id: str,
        response_summary: str,
        provider: str,
        model: str,
        token_usage: TokenUsage,
        latency_ms: int,
        metadata: dict[str, Any] | None = None,
    ) -> AuditResult:
        """Report LLM call details for audit logging."""
        return self._get_loop().run_until_complete(
            self._async_client.audit_llm_call(
                context_id, response_summary, provider, model, token_usage, latency_ms, metadata
            )
        )
