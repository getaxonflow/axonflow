"""Cache utilities for AxonFlow SDK."""

from __future__ import annotations

from typing import Any, Generic, TypeVar

from cachetools import TTLCache

T = TypeVar("T")


class CacheManager(Generic[T]):
    """Generic cache manager with TTL support.

    Provides a simple interface for caching with automatic expiration.
    """

    def __init__(self, maxsize: int = 1000, ttl: float = 60.0) -> None:
        """Initialize cache manager.

        Args:
            maxsize: Maximum number of entries
            ttl: Time-to-live in seconds
        """
        self._cache: TTLCache[str, T] = TTLCache(maxsize=maxsize, ttl=ttl)
        self._ttl = ttl
        self._maxsize = maxsize

    def get(self, key: str) -> T | None:
        """Get a value from cache.

        Args:
            key: Cache key

        Returns:
            Cached value or None if not found
        """
        return self._cache.get(key)

    def set(self, key: str, value: T) -> None:
        """Set a value in cache.

        Args:
            key: Cache key
            value: Value to cache
        """
        self._cache[key] = value

    def delete(self, key: str) -> None:
        """Delete a value from cache.

        Args:
            key: Cache key
        """
        self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached values."""
        self._cache.clear()

    def contains(self, key: str) -> bool:
        """Check if key exists in cache.

        Args:
            key: Cache key

        Returns:
            True if key exists
        """
        return key in self._cache

    @property
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)

    @property
    def ttl(self) -> float:
        """Get cache TTL."""
        return self._ttl

    @property
    def maxsize(self) -> int:
        """Get maximum cache size."""
        return self._maxsize

    def get_or_set(self, key: str, factory: Any) -> T:
        """Get from cache or create using factory.

        Args:
            key: Cache key
            factory: Callable to create value if not cached

        Returns:
            Cached or newly created value
        """
        value = self.get(key)
        if value is None:
            value = factory()
            self.set(key, value)
        return value
