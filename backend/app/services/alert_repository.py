from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from app.models.schemas import SIEMAlert
from app.services.config import settings
from app.services.resilience import CircuitBreaker, with_wazuh_fallback
from app.services.wazuh_indexer_client import WazuhIndexerClient
from app.services.wazuh_manager_client import WazuhManagerClient

logger = logging.getLogger(__name__)


class AlertRepository:
    def __init__(self) -> None:
        root = Path(__file__).resolve().parents[2]
        self._data_file = root / "data" / "alerts.json"
        self._wazuh_client = WazuhIndexerClient()
        self._manager_client = WazuhManagerClient()

    @property
    def indexer_breaker(self) -> CircuitBreaker:
        return self._wazuh_client.breaker

    @property
    def manager_breaker(self) -> CircuitBreaker:
        return self._manager_client.breaker

    def _load_demo_alerts(self) -> list[SIEMAlert]:
        payload = json.loads(self._data_file.read_text(encoding="utf-8"))
        return [SIEMAlert.model_validate(item) for item in payload]

    async def list_alerts_async(self) -> list[SIEMAlert]:
        if settings.app_mode != "wazuh":
            return self._load_demo_alerts()

        hits = await self._wazuh_client.search_alerts()
        alerts = [self._map_wazuh_hit(hit) for hit in hits]

        if settings.wazuh_enrich_with_agents and alerts:
            alerts = await self._enrich_with_agents(alerts)

        return alerts

    async def list_alerts_paged(self, page: int, size: int) -> tuple[list[SIEMAlert], int]:
        if settings.app_mode != "wazuh":
            all_alerts = self._load_demo_alerts()
            total = len(all_alerts)
            offset = (page - 1) * size
            return all_alerts[offset : offset + size], total

        from_ = (page - 1) * size
        hits_task = self._wazuh_client.search_alerts(size=size, from_=from_)
        count_task = self._wazuh_client.count_alerts()

        hits = await hits_task
        total = await count_task

        alerts = [self._map_wazuh_hit(hit) for hit in hits]
        if settings.wazuh_enrich_with_agents and alerts:
            alerts = await self._enrich_with_agents(alerts)

        return alerts, total

    async def get_alert_async(self, alert_id: str) -> SIEMAlert | None:
        if settings.app_mode != "wazuh":
            for alert in self._load_demo_alerts():
                if alert.id == alert_id:
                    return alert
            return None

        hit = await self._wazuh_client.get_alert_by_id(alert_id)
        if not hit:
            return None
        alert = self._map_wazuh_hit(hit)

        if settings.wazuh_enrich_with_agents:
            enriched = await self._enrich_with_agents([alert])
            return enriched[0]

        return alert

    def list_alerts(self) -> list[SIEMAlert]:
        return self._load_demo_alerts()

    def get_alert(self, alert_id: str) -> SIEMAlert | None:
        for alert in self._load_demo_alerts():
            if alert.id == alert_id:
                return alert
        return None

    async def _enrich_with_agents(
        self, alerts: list[SIEMAlert]
    ) -> list[SIEMAlert]:
        agent_ids = {
            alert.asset.hostname
            for alert in alerts
            if alert.asset.hostname and alert.asset.hostname not in {"unknown-host"}
        }
        if not agent_ids:
            return alerts

        async def _batch_fetch() -> dict[str, dict]:
            agents = await self._manager_client.list_agents(limit=500)
            agent_map: dict[str, dict] = {}
            for agent in agents:
                agent_id = agent.get("id")
                if agent_id and agent_id in agent_ids:
                    agent_map[agent_id] = agent
                # Also try by name
                agent_name = agent.get("name")
                if agent_name and agent_name in agent_ids:
                    agent_map[agent_name] = agent
            return agent_map

        agent_map = await with_wazuh_fallback(
            _batch_fetch,
            {},
            self._manager_client.breaker,
        )

        for alert in alerts:
            hostname = alert.asset.hostname
            if hostname and hostname in agent_map:
                agent = agent_map[hostname]
                alert.asset.hostname = agent.get("name") or agent.get("id") or hostname
                if agent.get("ip") and alert.asset.ip == "0.0.0.0":
                    alert.asset.ip = agent["ip"]

        return alerts

    async def list_wazuh_agents(self) -> list[dict]:
        return await self._manager_client.list_agents()

    async def get_wazuh_agent(self, agent_id: str) -> dict | None:
        return await self._manager_client.get_agent(agent_id)

    async def close(self) -> None:
        await self._wazuh_client.close()
        await self._manager_client.close()

    async def aggregate_incidents(self, top_n: int = 20) -> list[dict]:
        alerts = await self.list_alerts_async()
        groups: dict[str, dict] = {}
        sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        for alert in alerts:
            # 按攻击规则名称聚合（更有分析价值）
            key = alert.rule_name or alert.title
            if not key or len(key) < 3:
                continue
            if key not in groups:
                groups[key] = {
                    "source_ip": key,  # 复用字段存规则名
                    "count": 0,
                    "severities": {},
                    "latest": alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp),
                    "location": alert.event_type or "未知类型",
                    "key_alerts": [],
                }
            groups[key]["count"] += 1
            sev = alert.severity
            groups[key]["severities"][sev] = groups[key]["severities"].get(sev, 0) + 1
            # 更新时间戳
            groups[key]["latest"] = alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)

            key_list = groups[key]["key_alerts"]
            key_list.append({"id": alert.id, "title": alert.title, "severity": sev})
            key_list.sort(key=lambda x: sev_order.get(x["severity"], 0), reverse=True)
            if len(key_list) > 3:
                key_list.pop()

        sorted_groups = sorted(groups.values(), key=lambda x: x["count"], reverse=True)
        return sorted_groups[:top_n]

    async def update_alert_status(self, alert_id: str, new_status: str) -> SIEMAlert | None:
        alert = await self.get_alert_async(alert_id)
        if not alert:
            return None
        alert.status = new_status
        return alert

    async def wazuh_indexer_health(self) -> dict:
        return await self._wazuh_client.health_check()

    async def wazuh_manager_health(self) -> dict:
        return await self._manager_client.health_check()

    # ------------------------------------------------------------------
    # Wazuh OpenSearch hit → SIEMAlert 映射
    # ------------------------------------------------------------------

    def _map_wazuh_hit(self, hit: dict) -> SIEMAlert:  # noqa: C901
        source = hit.get("_source", {})
        rule = source.get("rule", {})
        agent = source.get("agent", {})
        data = source.get("data", {})
        predecoder = source.get("predecoder", {})
        timestamp = source.get("@timestamp") or datetime.utcnow().isoformat()

        # --- IP 提取 (多路径尝试) ---
        src_ip_candidates = [
            data.get("srcip"),
            data.get("src_ip"),
            source.get("srcip"),
            predecoder.get("srcip"),
        ]
        dst_ip_candidates = [
            data.get("dstip"),
            data.get("dest_ip"),
            data.get("dst_ip"),
            source.get("dstip"),
            predecoder.get("dstip"),
            agent.get("ip"),
        ]
        src_ip = next((str(x) for x in src_ip_candidates if x), "0.0.0.0")
        dst_ip = next((str(x) for x in dst_ip_candidates if x), "0.0.0.0")

        # --- 协议检测 ---
        protocol = self._detect_protocol(data, source)

        # --- 主机名 (多路径) ---
        hostname = (
            agent.get("name")
            or predecoder.get("hostname")
            or agent.get("id")
            or "unknown-host"
        )

        # --- 严重级别 ---
        level = int(rule.get("level", 0))
        severity = self._map_severity(level)

        # --- 告警标题 ---
        title = rule.get("description") or source.get("full_log") or "Wazuh Alert"

        # --- 日志摘要 ---
        full_log = source.get("full_log") or source.get("location") or title
        log_excerpt = full_log[:500] if full_log else title[:500]

        # --- 事件类型 ---
        event_type = self._determine_event_type(rule, source)

        # --- MITRE ATT&CK 战术 ---
        mitre_tactics = self._extract_mitre_tactics(rule)

        # --- 威胁类型 ---
        threat_type = self._infer_threat_type(rule, full_log)

        # --- 攻击阶段 ---
        attack_stage = self._infer_attack_stage(mitre_tactics)

        # --- 端口信息 ---
        src_port = data.get("srcport") or data.get("source_port") or 0
        dst_port = data.get("dstport") or data.get("dest_port") or data.get("destination_port") or 0
        proto_str = protocol if protocol != "unknown" else "TCP"

        return SIEMAlert.model_validate(
            {
                "id": hit.get("_id"),
                "title": title,
                "source": "wazuh",
                "severity": severity,
                "status": "new",
                "timestamp": timestamp,
                "rule_name": rule.get("description") or "Unknown Rule",
                "description": title,
                "log_excerpt": log_excerpt,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_geo": {
                    "region": "未知",
                    "country": "未知",
                    "city": "未知",
                    "latitude": 0,
                    "longitude": 0,
                },
                "event_type": event_type,
                "request_content": full_log or "",
                "packet_details": {
                    "protocol": proto_str,
                    "request_method": "unknown",
                    "request_uri": "/",
                    "source_port": int(src_port) if src_port else 0,
                    "destination_port": int(dst_port) if dst_port else 0,
                    "packet_size": 0,
                    "tcp_flags": "",
                    "payload_preview": full_log[:300] if full_log else "",
                },
                "threat_type": threat_type,
                "attack_stage": attack_stage,
                "related_rule_ids": [str(rule.get("id"))] if rule.get("id") else [],
                "hardening_suggestions": ["结合原始日志补充规则调优，并核验主机与账号侧安全基线"],
                "similar_incidents": {
                    "total": 0,
                    "last_7_days": 0,
                    "closed_rate": 0,
                },
                "ticket": {
                    "status": "pending",
                    "assignee": "system",
                    "updated_at": timestamp,
                    "response_minutes": 0,
                },
                "mitre_tactics": mitre_tactics,
                "asset": {
                    "hostname": hostname,
                    "ip": dst_ip,
                    "owner": agent.get("name") or agent.get("id") or "unknown",
                    "environment": "prod",
                },
                "related_entities": [
                    value
                    for value in [src_ip, dst_ip, agent.get("id"), hostname]
                    if value and value not in ("0.0.0.0", "unknown-host")
                ],
                "timeline": [
                    {
                        "timestamp": timestamp,
                        "message": full_log or title,
                    }
                ],
            }
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_protocol(data: dict, source: dict) -> str:
        if data.get("protocol"):
            return data["protocol"]
        win_data = data.get("win", {}).get("eventdata", {})
        if win_data.get("protocol"):
            return win_data["protocol"]
        if data.get("tls"):
            return "TLS"
        location = (source.get("location") or "").lower()
        if "syslog" in location:
            return "Syslog"
        return "unknown"

    @staticmethod
    def _determine_event_type(rule: dict, source: dict) -> str:
        decoder = source.get("decoder", {})
        decoder_name = (decoder.get("name") or "").lower()
        decoder_parent = (decoder.get("parent") or "").lower()

        if "syscheck" in decoder_name or "syscheck" in decoder_parent:
            return "文件完整性监控"
        if "windows-event" in decoder_name or "windows-event" in decoder_parent:
            return "Windows事件"
        if "aws" in decoder_name or "cloudtrail" in decoder_parent:
            return "AWS CloudTrail"
        if "pam" in decoder_name or "sshd" in decoder_name:
            return "认证日志"
        if "firewall" in decoder_name or "iptables" in decoder_parent:
            return "防火墙日志"

        groups = rule.get("groups", [])
        if groups:
            return str(groups[0])
        return "Wazuh告警"

    @staticmethod
    def _map_severity(level: int) -> str:
        if level >= 13:
            return "critical"
        if level >= 10:
            return "high"
        if level >= 6:
            return "medium"
        return "low"

    @staticmethod
    def _extract_mitre_tactics(rule: dict) -> list[str]:
        mitre = rule.get("mitre", {})
        tactics = mitre.get("tactic")
        if isinstance(tactics, list):
            return [str(item) for item in tactics]
        if isinstance(tactics, str) and tactics:
            return [tactics]
        return []

    @staticmethod
    def _infer_threat_type(rule: dict, full_log: str) -> str:
        text = " ".join(str(item) for item in rule.get("groups", []))
        text = f"{text} {rule.get('description', '')} {full_log}".lower()

        if "ransom" in text:
            return "ransomware"
        if "brute" in text or "ssh" in text or "failed" in text or "auth" in text:
            return "brute-force"
        if "miner" in text or "xmrig" in text or "crypto" in text:
            return "miner"
        if "c2" in text or "command and control" in text:
            return "c2"
        if "exfil" in text or "leak" in text or "data breach" in text:
            return "exfiltration"
        return "port-scan"

    @staticmethod
    def _infer_attack_stage(mitre_tactics: list[str]) -> str:
        tactic_text = " ".join(mitre_tactics).lower()
        if "exfiltration" in tactic_text:
            return "Exfiltration"
        if "command and control" in tactic_text:
            return "Command and Control"
        if "execution" in tactic_text:
            return "Execution"
        if "initial access" in tactic_text:
            return "Initial Access"
        return "Reconnaissance"
