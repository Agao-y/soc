from __future__ import annotations

from textwrap import dedent

import httpx

from app.models.schemas import SIEMAlert
from app.services.config import settings


class LLMClient:
    async def predict_attack_path(
        self,
        alert: SIEMAlert,
        cve_matches: list[dict],
        all_assets: list[str],
    ) -> str:
        """Predict next attack stage and likely targets based on current alert + CVE context."""
        if not settings.openai_api_key:
            return self._fallback_prediction(alert, cve_matches)

        cve_text = ""
        for c in cve_matches[:3]:
            cve_text += f"- {c['id']} (CVSS {c['cvss']}): {c['description'][:120]}\n"

        assets_text = ", ".join(all_assets[:12]) if all_assets else alert.asset.hostname
        stages_chain = " → ".join([
            "侦察(Reconnaissance)",
            "初始访问(Initial Access)",
            "执行(Execution)",
            "命令控制(Command and Control)",
            "数据渗出(Exfiltration)",
        ])

        prompt = (
            f"你是一名高级威胁狩猎分析师。请基于当前告警上下文，推理攻击者可能的下一步行动方向。\n\n"
            f"## 当前告警\n"
            f"- 攻击阶段: {alert.attack_stage}\n"
            f"- 威胁类型: {alert.threat_type}\n"
            f"- 源IP: {alert.source_ip} ({alert.source_geo.country})\n"
            f"- 目标资产: {alert.asset.hostname} ({alert.asset.ip}) / 环境: {alert.asset.environment}\n"
            f"- 严重级别: {alert.severity}\n"
            f"- MITRE 战术: {', '.join(alert.mitre_tactics) or '无'}\n"
            f"- 关联实体: {', '.join(alert.related_entities) or '无'}\n\n"
            f"## Kill Chain 阶段链\n{stages_chain}\n\n"
            f"## 目标资产匹配的高危 CVE\n{cve_text or '未发现直接关联的高危 CVE'}\n\n"
            f"## 网络内已知资产\n{assets_text}\n\n"
            f"## 日志片段\n{alert.log_excerpt[:300]}\n\n"
            f"请按以下格式输出推理结论（中文，简洁）：\n"
            f"1. **预测下一攻击阶段**: 从Kill Chain中选择最可能的下一阶段\n"
            f"2. **攻击路径推理**: 攻击者可能以什么方式推进攻击（结合CVE和资产信息）\n"
            f"3. **高风险目标**: 列出最可能被攻击的1-3个资产及其原因\n"
            f"4. **建议防御动作**: 具体的优先封堵措施\n"
            f"5. **风险评分**: 0-100 的数值评分\n\n"
            f"请确保推理有明确的因果逻辑链，基于当前攻击阶段、可用CVE、资产拓扑进行推断。"
        )

        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.openai_model,
            "messages": [
                {"role": "system", "content": "你是严谨的网络安全威胁狩猎分析师，擅长基于 Kill Chain 和 CVE 进行攻击路径推演。输出简洁、结构化、有因果逻辑的中文结论。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 400,
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

    def _fallback_prediction(self, alert: SIEMAlert, cve_matches: list[dict]) -> str:
        stages = ["Reconnaissance", "Initial Access", "Execution", "Command and Control", "Exfiltration"]
        try:
            idx = stages.index(alert.attack_stage)
            next_stage = stages[idx + 1] if idx < len(stages) - 1 else stages[-1]
        except ValueError:
            next_stage = "Execution"

        cve_hint = ""
        if cve_matches:
            cve_hint = f"。目标资产匹配到 {len(cve_matches)} 个高危 CVE: {', '.join(c['id'] for c in cve_matches[:3])}"

        return (
            f"1. **预测下一攻击阶段**: {next_stage}\n"
            f"2. **攻击路径推理**: 基于当前阶段 {alert.attack_stage} 和威胁类型 {alert.threat_type}，"
            f"攻击者极有可能尝试向 {next_stage} 阶段推进{cve_hint}。\n"
            f"3. **高风险目标**: {alert.asset.hostname}（当前目标），以及同网段可达资产\n"
            f"4. **建议防御动作**: 隔离 {alert.source_ip}，加固 {alert.asset.hostname} 相关服务，横向移动检测\n"
            f"5. **风险评分**: {min(95, 55 + len(cve_matches) * 10)}"
        )

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
            "max_tokens": 300,
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

    async def generate_narrative(
        self,
        target_alert: SIEMAlert,
        related_alerts: list[SIEMAlert],
    ) -> str:
        """Generate a complete attack narrative from a chain of related alerts."""
        if not settings.openai_api_key or not related_alerts:
            return self._fallback_narrative(target_alert, related_alerts)

        timeline_text = ""
        for i, a in enumerate(related_alerts, 1):
            timeline_text += (
                f"\n{i}. [{a.timestamp.isoformat()}] 阶段={a.attack_stage} | "
                f"类型={a.threat_type} | 严重={a.severity} | "
                f"源={a.source_ip} → 目标={a.asset.hostname}\n"
                f"   描述: {a.description}\n"
                f"   日志: {a.log_excerpt[:120]}\n"
            )

        prompt = (
            f"你是一名资深的网络安全事件调查分析师。请根据以下同一攻击者的告警时间线，"
            f"撰写一份完整的攻击事件分析报告，以通俗易懂但专业的方式讲述攻击故事。\n\n"
            f"## 攻击源\n"
            f"IP: {target_alert.source_ip} ({target_alert.source_geo.country}, {target_alert.source_geo.city})\n\n"
            f"## 告警时间线\n{timeline_text}\n\n"
            f"## 要求\n"
            f"请以自然段落形式撰写，包含以下内容，使用中文：\n"
            f"1. **攻击概述**: 用一段话总结这是一次什么样的攻击 (150字以内)\n"
            f"2. **攻击路径**: 从初始访问到最终目的的完整 Kill Chain 演进过程\n"
            f"3. **关键证据**: 从日志中提取最能说明攻击行为的证据\n"
            f"4. **影响评估**: 攻击对业务系统和数据可能造成的影响\n"
            f"5. **处置建议**: 按优先级列出具体可执行的处置步骤\n\n"
            f"注意：这是一份面向安全运维团队的正式报告，语言要专业、清晰、有条理。"
        )

        headers = {
            "Authorization": f"Bearer {settings.openai_api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": settings.openai_model,
            "messages": [
                {"role": "system", "content": "你是严谨的网络安全事件分析专家，擅长撰写攻击事件调查报告。"},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.4,
            "max_tokens": 1200,
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                f"{settings.openai_base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()

    def _fallback_narrative(
        self, alert: SIEMAlert, related: list[SIEMAlert]
    ) -> str:
        items = "\n".join(
            f"- {a.timestamp.isoformat()}: {a.attack_stage} / {a.threat_type} → {a.asset.hostname}"
            for a in related[:10]
        )
        return (
            f"## 攻击事件报告 (启发式生成)\n\n"
            f"**攻击源**: {alert.source_ip} ({alert.source_geo.country})\n\n"
            f"**关联告警**: {len(related)} 条\n\n"
            f"**告警时间线**:\n{items}\n\n"
            f"**初步判断**: 基于 {len(related)} 条关联告警，攻击者从 {alert.source_ip} "
            f"针对资产 {alert.asset.hostname} 发起了 {alert.threat_type} 类型攻击，"
            f"当前处于 {alert.attack_stage} 阶段。建议立即隔离涉事终端并展开横向移动排查。"
        )

    def _fallback(self, alert: SIEMAlert, heuristic_summary: str) -> str:
        return (
            f"综合规则特征与上下文，该告警更偏向{'真实威胁' if alert.severity in {'high', 'critical'} else '可疑事件'}。"
            f"重点关注资产 {alert.asset.hostname} 上的规则 {alert.rule_name}，"
            f"并结合日志片段与 MITRE 战术 {', '.join(alert.mitre_tactics) or '无'} 做进一步核验。"
            f" 启发式摘要：{heuristic_summary}"
        )
