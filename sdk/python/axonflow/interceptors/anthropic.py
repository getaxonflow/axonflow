"""Anthropic Interceptor for transparent governance.

Wraps Anthropic client to automatically apply AxonFlow governance
without changing application code.

Example:
    >>> from anthropic import Anthropic
    >>> from axonflow import AxonFlow
    >>> from axonflow.interceptors.anthropic import wrap_anthropic_client
    >>>
    >>> anthropic = Anthropic()
    >>> axonflow = AxonFlow(...)
    >>>
    >>> # Wrap the client - governance is now automatic
    >>> wrapped = wrap_anthropic_client(anthropic, axonflow)
    >>>
    >>> # Use as normal - governance happens invisibly
    >>> response = wrapped.messages.create(
    ...     model="claude-3-sonnet-20240229",
    ...     max_tokens=1024,
    ...     messages=[{"role": "user", "content": "Hello!"}]
    ... )
"""

from __future__ import annotations

import asyncio
from functools import wraps
from typing import TYPE_CHECKING, Any, Callable, TypeVar

from axonflow.exceptions import PolicyViolationError
from axonflow.interceptors.base import BaseInterceptor

if TYPE_CHECKING:
    from axonflow.client import AxonFlow

T = TypeVar("T")


class AnthropicInterceptor(BaseInterceptor):
    """Interceptor for Anthropic client."""

    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "anthropic"

    def extract_prompt(self, *_args: Any, **kwargs: Any) -> str:
        """Extract prompt from messages arguments."""
        messages = kwargs.get("messages", [])
        parts = []
        for m in messages:
            if isinstance(m, dict):
                content = m.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    # Handle content blocks
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
        return " ".join(parts)

    def wrap(self, client: Any) -> Any:
        """Wrap Anthropic client with governance."""
        return wrap_anthropic_client(client, self.axonflow, user_token=self.user_token)


def wrap_anthropic_client(
    anthropic_client: Any,
    axonflow: AxonFlow,
    *,
    user_token: str = "",
) -> Any:
    """Wrap Anthropic client with AxonFlow governance.

    Args:
        anthropic_client: Anthropic client to wrap
        axonflow: AxonFlow client for governance
        user_token: User token for policy evaluation

    Returns:
        Wrapped Anthropic client with automatic governance
    """
    original_create = anthropic_client.messages.create

    def _extract_prompt(kwargs: dict[str, Any]) -> str:
        """Extract prompt from messages."""
        messages = kwargs.get("messages", [])
        parts = []
        for m in messages:
            if isinstance(m, dict):
                content = m.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
        return " ".join(parts)

    def _get_loop() -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        try:
            return asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            return loop

    if asyncio.iscoroutinefunction(original_create):

        @wraps(original_create)
        async def async_wrapped_create(*args: Any, **kwargs: Any) -> Any:
            prompt = _extract_prompt(kwargs)

            # Check with AxonFlow
            response = await axonflow.execute_query(
                user_token=user_token,
                query=prompt,
                request_type="llm_chat",
                context={
                    "provider": "anthropic",
                    "model": kwargs.get("model", "claude-3-sonnet"),
                    "parameters": {
                        k: v
                        for k, v in kwargs.items()
                        if k not in ("messages", "model", "max_tokens")
                    },
                },
            )

            if response.blocked:
                raise PolicyViolationError(
                    response.block_reason or "Request blocked by policy"
                )

            # Call original
            return await original_create(*args, **kwargs)

        anthropic_client.messages.create = async_wrapped_create
    else:

        @wraps(original_create)
        def sync_wrapped_create(*args: Any, **kwargs: Any) -> Any:
            prompt = _extract_prompt(kwargs)

            # Check with AxonFlow (sync)
            loop = _get_loop()
            response = loop.run_until_complete(
                axonflow.execute_query(
                    user_token=user_token,
                    query=prompt,
                    request_type="llm_chat",
                    context={
                        "provider": "anthropic",
                        "model": kwargs.get("model", "claude-3-sonnet"),
                    },
                )
            )

            if response.blocked:
                raise PolicyViolationError(
                    response.block_reason or "Request blocked by policy"
                )

            # Call original
            return original_create(*args, **kwargs)

        anthropic_client.messages.create = sync_wrapped_create

    return anthropic_client


def create_anthropic_wrapper(
    axonflow: AxonFlow, user_token: str = ""
) -> Callable[[Any], Any]:
    """Create a wrapper function for Anthropic client.

    Args:
        axonflow: AxonFlow client for governance
        user_token: User token for policy evaluation

    Returns:
        Wrapper function that takes an Anthropic client
    """

    def wrapper(anthropic_client: Any) -> Any:
        return wrap_anthropic_client(anthropic_client, axonflow, user_token=user_token)

    return wrapper
