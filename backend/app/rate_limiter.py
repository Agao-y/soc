import time
from collections import defaultdict

from fastapi import HTTPException, Request, status


class RateLimiter:
    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._store: dict[str, list[float]] = defaultdict(list)

    def _clean(self, key: str, now: float) -> None:
        cutoff = now - self.window
        self._store[key] = [t for t in self._store[key] if t > cutoff]
        if not self._store[key]:
            del self._store[key]

    def check(self, key: str) -> None:
        now = time.time()
        self._clean(key, now)
        if len(self._store[key]) >= self.max_attempts:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="请求过于频繁，请稍后再试",
            )
        self._store[key].append(now)


login_limiter = RateLimiter(max_attempts=5, window_seconds=60)
register_limiter = RateLimiter(max_attempts=3, window_seconds=60)


def get_client_ip(request: Request) -> str:
    # 只用直连 IP，不信任 X-Forwarded-For 头（防止伪造绕过速率限制）
    host = request.client.host if request.client else "unknown"
    return host
