"""Base Interceptor class for LLM providers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from axonflow.client import AxonFlow


class BaseInterceptor(ABC):
    """Base class for LLM provider interceptors.

    Interceptors wrap LLM client methods to automatically apply
    AxonFlow governance without changing application code.
    """

    def __init__(self, axonflow: AxonFlow, user_token: str = "") -> None:
        """Initialize interceptor.

        Args:
            axonflow: AxonFlow client for governance
            user_token: User token for policy evaluation
        """
        self.axonflow = axonflow
        self.user_token = user_token

    @abstractmethod
    def wrap(self, client: Any) -> Any:
        """Wrap an LLM client with governance.

        Args:
            client: The LLM client to wrap

        Returns:
            Wrapped client with automatic governance
        """

    @abstractmethod
    def extract_prompt(self, *args: Any, **kwargs: Any) -> str:
        """Extract prompt from method arguments.

        Args:
            args: Positional arguments
            kwargs: Keyword arguments

        Returns:
            Extracted prompt string
        """

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the provider name.

        Returns:
            Provider name (e.g., "openai", "anthropic")
        """
