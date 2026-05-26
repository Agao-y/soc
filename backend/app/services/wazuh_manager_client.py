from __future__ import annotations

import logging
import time
from typing import Any

import httpx

from app.services.config import settings
from app.services.resilience import CircuitBreaker, with_wazuh_fallback

logger = logging.getLogger(__name__)


class WazuhManagerClient:
    def __init__(self) -> None:
        self._base_url = settings.wazuh_manager_url.rstrip("/")
        self._username = settings.wazuh_manager_username
        self._password = settings.wazuh_manager_password
        self._verify = settings.wazuh_manager_verify_ssl
        self._timeout = settings.wazuh_request_timeout
        self._breaker = CircuitBreaker(
            name="wazuh-manager",
            threshold=settings.wazuh_circuit_breaker_threshold,
            cooldown_seconds=settings.wazuh_circuit_breaker_cooldown,
        )
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._client: httpx.AsyncClient | None = None

    @property
    def breaker(self) -> CircuitBreaker:
        return self._breaker

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self._verify,
                timeout=self._timeout,
                trust_env=False,
            )
        return self._client

    async def _authenticate(self) -> str:
        """获取 JWT token。若已缓存且未过期则直接返回。"""
        if self._token and time.monotonic() < self._token_expiry:
            return self._token

        resp = await self.client.post(
            f"{self._base_url}/security/user/authenticate",
            json={"username": self._username, "password": self._password},
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["data"]["token"]
        # Wazuh token 默认 900 秒有效期，提前 60 秒刷新
        self._token_expiry = time.monotonic() + 840
        return self._token

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        token = await self._authenticate()
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        return await self.client.request(
            method, f"{self._base_url}{path}", headers=headers, **kwargs
        )

    async def health_check(self) -> dict[str, Any]:
        async def _check() -> dict[str, Any]:
            resp = await self._request("GET", "/")
            resp.raise_for_status()
            data = resp.json()
            return {
                "ok": True,
                "version": data.get("data", {}).get("api_version", "unknown"),
            }

        return await with_wazuh_fallback(
            _check,
            {"ok": False, "error": "manager unreachable"},
            self._breaker,
        )

    async def list_agents(
        self, limit: int = 100, offset: int = 0
    ) -> list[dict[str, Any]]:
        async def _list() -> list[dict[str, Any]]:
            resp = await self._request(
                "GET",
                "/agents",
                params={"limit": limit, "offset": offset, "select": "id,name,ip,status,os.name,os.version"},
            )
            resp.raise_for_status()
            data = resp.json()
            # data.data.affected_items is the agent list
            return data.get("data", {}).get("affected_items", [])

        return await with_wazuh_fallback(_list, [], self._breaker)

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        async def _get() -> dict[str, Any] | None:
            resp = await self._request("GET", f"/agents/{agent_id}")
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else None

        return await with_wazuh_fallback(_get, None, self._breaker)

    async def get_manager_info(self) -> dict[str, Any]:
        async def _info() -> dict[str, Any]:
            resp = await self._request("GET", "/manager/info")
            resp.raise_for_status()
            data = resp.json()
            items = data.get("data", {}).get("affected_items", [])
            return items[0] if items else {}

        return await with_wazuh_fallback(_info, {}, self._breaker)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
