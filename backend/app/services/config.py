from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    app_mode: str = os.getenv("APP_MODE", "demo")
    wazuh_indexer_url: str = os.getenv("WAZUH_INDEXER_URL", "")
    wazuh_indexer_username: str = os.getenv("WAZUH_INDEXER_USERNAME", "")
    wazuh_indexer_password: str = os.getenv("WAZUH_INDEXER_PASSWORD", "")
    wazuh_indexer_verify_ssl: bool = os.getenv("WAZUH_INDEXER_VERIFY_SSL", "true").lower() == "true"
    wazuh_alert_index: str = os.getenv("WAZUH_ALERT_INDEX", "wazuh-alerts*")
    wazuh_manager_url: str = os.getenv("WAZUH_MANAGER_URL", "")
    wazuh_manager_username: str = os.getenv("WAZUH_MANAGER_USERNAME", "")
    wazuh_manager_password: str = os.getenv("WAZUH_MANAGER_PASSWORD", "")
    wazuh_manager_verify_ssl: bool = os.getenv("WAZUH_MANAGER_VERIFY_SSL", "true").lower() == "true"
    wazuh_request_timeout: int = int(os.getenv("WAZUH_REQUEST_TIMEOUT", "30"))
    wazuh_max_retries: int = int(os.getenv("WAZUH_MAX_RETRIES", "2"))
    wazuh_circuit_breaker_threshold: int = int(os.getenv("WAZUH_CIRCUIT_BREAKER_THRESHOLD", "3"))
    wazuh_circuit_breaker_cooldown: int = int(os.getenv("WAZUH_CIRCUIT_BREAKER_COOLDOWN", "60"))
    wazuh_enrich_with_agents: bool = os.getenv("WAZUH_ENRICH_WITH_AGENTS", "true").lower() == "true"


settings = Settings()
