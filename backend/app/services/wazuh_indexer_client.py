from __future__ import annotations

import logging
from typing import Any

import httpx

from app.services.config import settings
from app.services.resilience import CircuitBreaker, with_wazuh_fallback

logger = logging.getLogger(__name__)


class WazuhIndexerClient:
    def __init__(self) -> None:
        self._base_url = settings.wazuh_indexer_url.rstrip("/")
        self._auth: tuple[str, str] = (
            settings.wazuh_indexer_username,
            settings.wazuh_indexer_password,
        )
        self._verify = settings.wazuh_indexer_verify_ssl
        self._timeout = settings.wazuh_request_timeout
        self._alert_index = settings.wazuh_alert_index
        self._breaker = CircuitBreaker(
            name="wazuh-indexer",
            threshold=settings.wazuh_circuit_breaker_threshold,
            cooldown_seconds=settings.wazuh_circuit_breaker_cooldown,
        )
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
                auth=self._auth,
                trust_env=False,
            )
        return self._client

    async def health_check(self) -> dict[str, Any]:
        async def _check() -> dict[str, Any]:
            resp = await self.client.get(f"{self._base_url}/_cluster/health")
            resp.raise_for_status()
            data = resp.json()
            return {
                "ok": True,
                "status": data.get("status", "unknown"),
                "cluster_name": data.get("cluster_name", ""),
            }

        return await with_wazuh_fallback(
            _check,
            {"ok": False, "error": "indexer unreachable"},
            self._breaker,
        )

    async def search_alerts(
        self,
        size: int = 50,
        from_ts: str | None = None,
        to_ts: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._base_url:
            logger.debug("Wazuh Indexer URL 未配置, 返回空列表")
            return []

        range_query: dict[str, Any] = {"gte": from_ts or "now-24h"}
        if to_ts:
            range_query["lte"] = to_ts

        async def _search() -> list[dict[str, Any]]:
            payload: dict[str, Any] = {
                "size": size,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"range": {"@timestamp": range_query}},
            }
            resp = await self.client.post(
                f"{self._base_url}/{self._alert_index}/_search",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("hits", {}).get("hits", [])

        return await with_wazuh_fallback(_search, [], self._breaker)

    async def get_alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        if not self._base_url:
            return None

        async def _get() -> dict[str, Any] | None:
            payload: dict[str, Any] = {
                "size": 1,
                "query": {"ids": {"values": [alert_id]}},
            }
            resp = await self.client.post(
                f"{self._base_url}/{self._alert_index}/_search",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            return hits[0] if hits else None

        return await with_wazuh_fallback(_get, None, self._breaker)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None
