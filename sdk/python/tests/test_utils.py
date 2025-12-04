"""Tests for utility modules."""

from __future__ import annotations

from axonflow.types import RetryConfig
from axonflow.utils.cache import CacheManager
from axonflow.utils.retry import RetryHandler, create_retry_decorator, with_retry


class TestCacheManager:
    """Test CacheManager utility."""

    def test_create_cache(self) -> None:
        """Test creating cache manager."""
        cache: CacheManager[str] = CacheManager(maxsize=100, ttl=30.0)
        assert cache.maxsize == 100
        assert cache.ttl == 30.0

    def test_set_and_get(self) -> None:
        """Test setting and getting values."""
        cache: CacheManager[str] = CacheManager()
        cache.set("key1", "value1")
        assert cache.get("key1") == "value1"

    def test_get_missing_key(self) -> None:
        """Test getting non-existent key."""
        cache: CacheManager[str] = CacheManager()
        assert cache.get("missing") is None

    def test_delete(self) -> None:
        """Test deleting a key."""
        cache: CacheManager[str] = CacheManager()
        cache.set("key", "value")
        cache.delete("key")
        assert cache.get("key") is None

    def test_delete_missing_key(self) -> None:
        """Test deleting non-existent key doesn't raise."""
        cache: CacheManager[str] = CacheManager()
        cache.delete("missing")  # Should not raise

    def test_clear(self) -> None:
        """Test clearing all values."""
        cache: CacheManager[str] = CacheManager()
        cache.set("key1", "value1")
        cache.set("key2", "value2")
        cache.clear()
        assert cache.size == 0

    def test_contains(self) -> None:
        """Test checking if key exists."""
        cache: CacheManager[str] = CacheManager()
        cache.set("key", "value")
        assert cache.contains("key") is True
        assert cache.contains("missing") is False

    def test_size(self) -> None:
        """Test getting cache size."""
        cache: CacheManager[str] = CacheManager()
        assert cache.size == 0
        cache.set("key1", "value1")
        assert cache.size == 1
        cache.set("key2", "value2")
        assert cache.size == 2

    def test_get_or_set(self) -> None:
        """Test get_or_set functionality."""
        cache: CacheManager[int] = CacheManager()
        factory_called = [0]

        def factory() -> int:
            factory_called[0] += 1
            return 42

        # First call should invoke factory
        result1 = cache.get_or_set("key", factory)
        assert result1 == 42
        assert factory_called[0] == 1

        # Second call should use cached value
        result2 = cache.get_or_set("key", factory)
        assert result2 == 42
        assert factory_called[0] == 1  # Factory not called again

    def test_generic_typing(self) -> None:
        """Test generic typing works."""
        int_cache: CacheManager[int] = CacheManager()
        int_cache.set("number", 42)
        assert int_cache.get("number") == 42

        dict_cache: CacheManager[dict[str, str]] = CacheManager()
        dict_cache.set("data", {"key": "value"})
        assert dict_cache.get("data") == {"key": "value"}


class TestRetryHandler:
    """Test RetryHandler utility."""

    def test_create_handler(self) -> None:
        """Test creating retry handler."""
        config = RetryConfig()
        handler = RetryHandler(config)
        assert handler.config == config

    def test_disabled_retry(self) -> None:
        """Test disabled retry returns identity decorator."""
        config = RetryConfig(enabled=False)
        handler = RetryHandler(config)

        def my_func() -> str:
            return "hello"

        decorator = handler.create_decorator((Exception,))
        decorated = decorator(my_func)

        assert decorated() == "hello"

    def test_enabled_retry_decorator(self) -> None:
        """Test enabled retry creates decorator."""
        config = RetryConfig(enabled=True, max_attempts=3)
        handler = RetryHandler(config)

        call_count = [0]

        def flaky_func() -> str:
            call_count[0] += 1
            if call_count[0] < 3:
                msg = "Temporary error"
                raise ValueError(msg)
            return "success"

        decorator = handler.create_decorator((ValueError,))
        decorated = decorator(flaky_func)

        result = decorated()
        assert result == "success"
        assert call_count[0] == 3


class TestWithRetryDecorator:
    """Test with_retry decorator."""

    def test_with_retry_basic(self) -> None:
        """Test basic retry functionality."""
        call_count = [0]

        @with_retry(max_attempts=3, retry_on=(ValueError,))
        def my_func() -> str:
            call_count[0] += 1
            if call_count[0] < 2:
                msg = "Error"
                raise ValueError(msg)
            return "done"

        result = my_func()
        assert result == "done"
        assert call_count[0] == 2

    def test_with_retry_exhausted(self) -> None:
        """Test retry exhaustion."""
        import pytest

        @with_retry(max_attempts=2, retry_on=(ValueError,))
        def always_fails() -> None:
            msg = "Always fails"
            raise ValueError(msg)

        with pytest.raises(ValueError):
            always_fails()


class TestCreateRetryDecorator:
    """Test create_retry_decorator function."""

    def test_create_decorator(self) -> None:
        """Test creating decorator from config."""
        config = RetryConfig(enabled=True, max_attempts=2)
        decorator = create_retry_decorator(config, (RuntimeError,))

        call_count = [0]

        def my_func() -> str:
            call_count[0] += 1
            if call_count[0] < 2:
                msg = "Error"
                raise RuntimeError(msg)
            return "ok"

        decorated = decorator(my_func)
        result = decorated()
        assert result == "ok"
