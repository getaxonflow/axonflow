"""Retry utilities for AxonFlow SDK."""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from axonflow.types import RetryConfig

T = TypeVar("T")


class RetryHandler:
    """Handles retry logic with exponential backoff."""

    def __init__(self, config: RetryConfig) -> None:
        """Initialize retry handler.

        Args:
            config: Retry configuration
        """
        self.config = config

    def create_decorator(
        self,
        retry_on: tuple[type[Exception], ...],
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Create retry decorator based on config.

        Args:
            retry_on: Exception types to retry on

        Returns:
            Decorator function
        """
        if not self.config.enabled:
            return lambda f: f

        return retry(
            stop=stop_after_attempt(self.config.max_attempts),
            wait=wait_exponential(
                multiplier=self.config.initial_delay,
                max=self.config.max_delay,
                exp_base=self.config.exponential_base,
            ),
            retry=retry_if_exception_type(retry_on),
            reraise=True,
        )

    @staticmethod
    def log_retry(retry_state: RetryCallState) -> None:
        """Log retry attempt.

        Args:
            retry_state: Current retry state
        """
        if retry_state.outcome and retry_state.outcome.failed:
            exception = retry_state.outcome.exception()
            attempt = retry_state.attempt_number
            print(f"Retry attempt {attempt} failed: {exception}")


def with_retry(
    max_attempts: int = 3,
    initial_delay: float = 1.0,
    max_delay: float = 30.0,
    exponential_base: float = 2.0,
    retry_on: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for adding retry logic to a function.

    Args:
        max_attempts: Maximum retry attempts
        initial_delay: Initial delay between retries
        max_delay: Maximum delay between retries
        exponential_base: Exponential backoff base
        retry_on: Exception types to retry on

    Returns:
        Decorator function
    """
    config = RetryConfig(
        enabled=True,
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
    )
    handler = RetryHandler(config)
    return handler.create_decorator(retry_on)


def create_retry_decorator(
    config: RetryConfig, retry_on: tuple[type[Exception], ...]
) -> Any:
    """Create a retry decorator from config.

    Args:
        config: Retry configuration
        retry_on: Exception types to retry on

    Returns:
        Retry decorator
    """
    handler = RetryHandler(config)
    return handler.create_decorator(retry_on)
