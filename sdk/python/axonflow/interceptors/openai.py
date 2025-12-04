"""OpenAI Interceptor for transparent governance.

Wraps OpenAI client to automatically apply AxonFlow governance
without changing application code.

Example:
    >>> from openai import OpenAI
    >>> from axonflow import AxonFlow
    >>> from axonflow.interceptors.openai import wrap_openai_client
    >>>
    >>> openai = OpenAI()
    >>> axonflow = AxonFlow(...)
    >>>
    >>> # Wrap the client - governance is now automatic
    >>> wrapped = wrap_openai_client(openai, axonflow)
    >>>
    >>> # Use as normal - governance happens invisibly
    >>> response = wrapped.chat.completions.create(
    ...     model="gpt-4",
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


class OpenAIInterceptor(BaseInterceptor):
    """Interceptor for OpenAI client."""

    def get_provider_name(self) -> str:
        """Get the provider name."""
        return "openai"

    def extract_prompt(self, *_args: Any, **kwargs: Any) -> str:
        """Extract prompt from chat completions arguments."""
        messages = kwargs.get("messages", [])
        return " ".join(m.get("content", "") for m in messages if isinstance(m, dict))

    def wrap(self, client: Any) -> Any:
        """Wrap OpenAI client with governance."""
        return wrap_openai_client(client, self.axonflow, user_token=self.user_token)


def wrap_openai_client(
    openai_client: Any,
    axonflow: AxonFlow,
    *,
    user_token: str = "",
) -> Any:
    """Wrap OpenAI client with AxonFlow governance.

    Args:
        openai_client: OpenAI client to wrap
        axonflow: AxonFlow client for governance
        user_token: User token for policy evaluation

    Returns:
        Wrapped OpenAI client with automatic governance
    """
    original_create = openai_client.chat.completions.create

    def _extract_prompt(kwargs: dict[str, Any]) -> str:
        """Extract prompt from messages."""
        messages = kwargs.get("messages", [])
        return " ".join(m.get("content", "") for m in messages if isinstance(m, dict))

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
                    "provider": "openai",
                    "model": kwargs.get("model", "gpt-4"),
                    "parameters": {
                        k: v for k, v in kwargs.items() if k not in ("messages", "model")
                    },
                },
            )

            if response.blocked:
                raise PolicyViolationError(
                    response.block_reason or "Request blocked by policy"
                )

            # Call original
            return await original_create(*args, **kwargs)

        openai_client.chat.completions.create = async_wrapped_create
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
                        "provider": "openai",
                        "model": kwargs.get("model", "gpt-4"),
                    },
                )
            )

            if response.blocked:
                raise PolicyViolationError(
                    response.block_reason or "Request blocked by policy"
                )

            # Call original
            return original_create(*args, **kwargs)

        openai_client.chat.completions.create = sync_wrapped_create

    return openai_client


def create_openai_wrapper(axonflow: AxonFlow, user_token: str = "") -> Callable[[Any], Any]:
    """Create a wrapper function for OpenAI client.

    Args:
        axonflow: AxonFlow client for governance
        user_token: User token for policy evaluation

    Returns:
        Wrapper function that takes an OpenAI client
    """

    def wrapper(openai_client: Any) -> Any:
        return wrap_openai_client(openai_client, axonflow, user_token=user_token)

    return wrapper
