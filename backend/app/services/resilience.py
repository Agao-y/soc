from __future__ import annotations

import enum
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """熔断器已打开，请求被拦截。"""


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        threshold: int = 3,
        cooldown_seconds: float = 60.0,
    ) -> None:
        self.name = name
        self.threshold = threshold
        self.cooldown = cooldown_seconds
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._state = CircuitState.CLOSED

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.cooldown:
                self._state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker [%s] 进入 HALF_OPEN 探测状态", self.name)
        return self._state

    def success(self) -> None:
        if self._state != CircuitState.CLOSED:
            logger.info("Circuit breaker [%s] 恢复 CLOSED", self.name)
        self._failure_count = 0
        self._state = CircuitState.CLOSED

    def failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._failure_count >= self.threshold and self._state == CircuitState.CLOSED:
            self._state = CircuitState.OPEN
            logger.warning(
                "Circuit breaker [%s] 熔断打开 (连续失败 %d 次, 冷却 %ds)",
                self.name,
                self._failure_count,
                self.cooldown,
            )

    def allow_request(self) -> bool:
        return self.state != CircuitState.OPEN

    @property
    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    @property
    def failure_count(self) -> int:
        return self._failure_count


async def with_wazuh_fallback(
    coro_factory: Callable[[], Awaitable[T]],
    fallback_value: T,
    breaker: CircuitBreaker,
    *,
    retries: int = 0,
) -> T:
    if not breaker.allow_request():
        logger.debug("Circuit breaker [%s] 已打开, 返回降级值", breaker.name)
        return fallback_value

    last_exception: Exception | None = None
    for attempt in range(retries + 1):
        try:
            result = await coro_factory()
            breaker.success()
            return result
        except Exception as exc:
            last_exception = exc
            if attempt < retries:
                logger.debug(
                    "Wazuh 请求失败 (尝试 %d/%d): %s",
                    attempt + 1,
                    retries + 1,
                    exc,
                )

    breaker.failure()
    logger.warning(
        "Wazuh 请求失败 [%s]: %s, 返回降级值",
        breaker.name,
        last_exception,
    )
    return fallback_value
