from __future__ import annotations

from textwrap import dedent

import httpx

from app.models.schemas import SIEMAlert
from app.services.config import settings


class LLMClient:
    async def analyze(self, alert: SIEMAlert, heuristic_summary: str) -> str:
        if not settings.openai_api_key:
            return self._fallback(alert, heuristic_summary)

        prompt = dedent(
            f"""
            你是一名高级 SOC 分析师。请结合 SIEM 告警上下文，输出简洁的中文研判结论。
            要求包含：
            1. 威胁真实性判断
            2. 关键证据
            3. 建议处置动作

            告警标题: {alert.title}
            来源: {alert.source}
            严重级别: {alert.severity}
            规则: {alert.rule_name}
            描述: {alert.description}
            日志片段: {alert.log_excerpt}
            资产: {alert.asset.hostname} / {alert.asset.ip} / {alert.asset.environment}
            MITRE: {", ".join(alert.mitre_tactics)}
            关联实体: {", ".join(alert.related_entities)}

            启发式分析摘要:
            {heuristic_summary}
            """
        ).strip()

        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.openai_model,
            "messages": [
                {"role": "system", "content": "你是严谨的网络安全威胁分析助手。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{settings.openai_base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()

    def _fallback(self, alert: SIEMAlert, heuristic_summary: str) -> str:
        return (
            f"综合规则特征与上下文，该告警更偏向{'真实威胁' if alert.severity in {'high', 'critical'} else '可疑事件'}。"
            f"重点关注资产 {alert.asset.hostname} 上的规则 {alert.rule_name}，"
            f"并结合日志片段与 MITRE 战术 {', '.join(alert.mitre_tactics) or '无'} 做进一步核验。"
            f" 启发式摘要：{heuristic_summary}"
        )
