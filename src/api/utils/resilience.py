"""
Production-Ready Error Handling and Retry Logic
Implements resilience patterns: retry with exponential backoff, circuit breakers, timeouts
"""

import asyncio
import time
import functools
from typing import Callable, TypeVar, Optional, Type, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(str, Enum):
    """Circuit breaker states"""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


class CircuitBreaker:
    """
    Circuit breaker pattern implementation
    Prevents cascading failures by failing fast when error threshold is exceeded
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        expected_exception: Type[Exception] = Exception,
        name: str = "circuit_breaker"
    ):
        """
        Initialize circuit breaker

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
            expected_exception: Exception type to track for failures
            name: Circuit breaker identifier for logging
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.name = name

        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.state = CircuitState.CLOSED

    def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function with circuit breaker protection"""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                logger.info(f"Circuit breaker {self.name}: Attempting reset (half-open)")
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception(f"Circuit breaker {self.name} is OPEN")

        try:
            result = func(*args, **kwargs)
            self._on_success()
            return result

        except self.expected_exception as e:
            self._on_failure()
            raise e

    async def call_async(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute async function with circuit breaker protection"""
        if self.state == CircuitState.OPEN:
            if self._should_attempt_reset():
                logger.info(f"Circuit breaker {self.name}: Attempting reset (half-open)")
                self.state = CircuitState.HALF_OPEN
            else:
                raise Exception(f"Circuit breaker {self.name} is OPEN")

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result

        except self.expected_exception as e:
            self._on_failure()
            raise e

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset"""
        if self.last_failure_time is None:
            return False
        return time.time() - self.last_failure_time >= self.recovery_timeout

    def _on_success(self):
        """Handle successful call"""
        if self.state == CircuitState.HALF_OPEN:
            logger.info(f"Circuit breaker {self.name}: Service recovered, closing circuit")
        self.failure_count = 0
        self.state = CircuitState.CLOSED

    def _on_failure(self):
        """Handle failed call"""
        self.failure_count += 1
        self.last_failure_time = time.time()

        logger.warning(
            f"Circuit breaker {self.name}: Failure {self.failure_count}/{self.failure_threshold}"
        )

        if self.failure_count >= self.failure_threshold:
            logger.error(f"Circuit breaker {self.name}: OPENING circuit due to failures")
            self.state = CircuitState.OPEN

    def reset(self):
        """Manually reset circuit breaker"""
        self.failure_count = 0
        self.state = CircuitState.CLOSED
        self.last_failure_time = None
        logger.info(f"Circuit breaker {self.name}: Manually reset")


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable[[Exception, int], None]] = None
):
    """
    Decorator for retry with exponential backoff

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries (seconds)
        max_delay: Maximum delay between retries (seconds)
        exponential_base: Base for exponential backoff calculation
        exceptions: Tuple of exception types to retry on
        on_retry: Callback function called on each retry

    Example:
        @retry_with_backoff(max_retries=3, base_delay=1.0)
        async def fetch_data():
            # Your code here
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt == max_retries:
                        logger.error(
                            f"{func.__name__}: All {max_retries} retries exhausted",
                            exc_info=True
                        )
                        raise

                    # Calculate exponential backoff delay
                    delay = min(base_delay * (exponential_base ** attempt), max_delay)

                    logger.warning(
                        f"{func.__name__}: Attempt {attempt + 1}/{max_retries + 1} failed, "
                        f"retrying in {delay:.2f}s: {str(e)}"
                    )

                    if on_retry:
                        on_retry(e, attempt + 1)

                    await asyncio.sleep(delay)

            # Should never reach here, but just in case
            if last_exception:
                raise last_exception

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e

                    if attempt == max_retries:
                        logger.error(
                            f"{func.__name__}: All {max_retries} retries exhausted",
                            exc_info=True
                        )
                        raise

                    delay = min(base_delay * (exponential_base ** attempt), max_delay)

                    logger.warning(
                        f"{func.__name__}: Attempt {attempt + 1}/{max_retries + 1} failed, "
                        f"retrying in {delay:.2f}s: {str(e)}"
                    )

                    if on_retry:
                        on_retry(e, attempt + 1)

                    time.sleep(delay)

            if last_exception:
                raise last_exception

        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper

    return decorator


def timeout(seconds: float):
    """
    Decorator to add timeout to async functions

    Args:
        seconds: Timeout duration in seconds

    Example:
        @timeout(30.0)
        async def long_running_task():
            # Your code here
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                logger.error(f"{func.__name__}: Timeout after {seconds}s")
                raise TimeoutError(f"Function {func.__name__} timed out after {seconds}s")

        return wrapper
    return decorator


class GracefulDegradation:
    """
    Context manager for graceful degradation
    Provides fallback behavior when primary operation fails
    """

    def __init__(self, fallback_value=None, log_errors: bool = True):
        """
        Initialize graceful degradation handler

        Args:
            fallback_value: Value to return on failure
            log_errors: Whether to log errors
        """
        self.fallback_value = fallback_value
        self.log_errors = log_errors
        self.exception: Optional[Exception] = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is not None:
            self.exception = exc_val
            if self.log_errors:
                logger.warning(
                    f"Graceful degradation: Caught {exc_type.__name__}: {exc_val}",
                    exc_info=(exc_type, exc_val, exc_tb)
                )
            return True  # Suppress exception
        return False

    def get_value(self, default=None):
        """Get fallback value or default"""
        return self.fallback_value if self.fallback_value is not None else default


# Example usage:

# Circuit breaker for external API calls
api_circuit_breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=60,
    expected_exception=Exception,
    name="external_api"
)

# Database circuit breaker
db_circuit_breaker = CircuitBreaker(
    failure_threshold=3,
    recovery_timeout=30,
    expected_exception=Exception,
    name="database"
)


@retry_with_backoff(max_retries=3, base_delay=1.0, exceptions=(ConnectionError, TimeoutError))
@timeout(30.0)
async def fetch_external_data(url: str):
    """
    Example function with retry and timeout
    Automatically retries on connection errors with exponential backoff
    Times out after 30 seconds
    """
    async def _fetch():
        # Your actual implementation
        pass

    return await api_circuit_breaker.call_async(_fetch)


def expensive_operation_that_might_fail():
    """Placeholder function that might raise an exception"""
    # This is a stub for demonstration purposes
    # Replace with actual implementation
    raise Exception("Operation failed")


def graceful_operation_example():
    """Example of graceful degradation"""
    with GracefulDegradation(fallback_value=[]) as gd:
        # Attempt primary operation
        result = expensive_operation_that_might_fail()

    # If it failed, use fallback value
    return gd.get_value(default=[])
