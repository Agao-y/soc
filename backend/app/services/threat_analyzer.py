from __future__ import annotations

import asyncio
from collections import Counter

from app.models.schemas import (
    AlertDetailResponse,
    AssessmentExplainability,
    AttackPrediction,
    DashboardMetric,
    DashboardResponse,
    DistributionSlice,
    ExplainabilityRow,
    GaugeRange,
    GeoAttackPoint,
    RiskGauge,
    SIEMAlert,
    ThreatAssessment,
    TicketFlowSummary,
)
from app.services.alert_repository import AlertRepository
from app.services.cve_lookup import search_cve_by_asset
from app.services.llm_client import LLMClient


class ThreatAnalyzer:
    def __init__(self, repository: AlertRepository, llm_client: LLMClient) -> None:
        self.repository = repository
        self.llm_client = llm_client

    async def generate_narrative(self, alert_id: str) -> str | None:
        """Find related alerts from same source IP and generate an attack narrative."""
        try:
            target = await self.repository.get_alert_async(alert_id)
            if not target:
                return None

            all_alerts = await self.repository.list_alerts_async(limit=200)
            related = [
                a for a in all_alerts
                if a.source_ip == target.source_ip
            ]
            related.sort(key=lambda a: a.timestamp)

            if len(related) < 2:
                related = [a for a in all_alerts if a.id == alert_id] + [
                    a for a in all_alerts
                    if a.asset.hostname == target.asset.hostname and a.id != alert_id
                ][:4]

            return await self.llm_client.generate_narrative(target, related)
        except Exception:
            return None

    async def analyze_alert(self, alert_id: str) -> AlertDetailResponse | None:
        alert = await self.repository.get_alert_async(alert_id)
        if not alert:
            return None

        heuristic = self._heuristic_scores(alert)

        # CVE 关联 (本地缓存 + NVD 实时查询)
        cve_matches = await search_cve_by_asset(
            hostname=alert.asset.hostname,
            log_text=alert.log_excerpt + " " + alert.description,
            service_hints=[alert.threat_type, alert.attack_stage],
        )

        all_assets = self.repository.get_asset_list()

        # 并行调用 LLM：分析 + 预测
        tasks = [self.llm_client.analyze(alert, heuristic["summary"])]
        need_prediction = heuristic["label"] in ("suspicious", "confirmed-threat")
        if need_prediction:
            tasks.append(self.llm_client.predict_attack_path(alert, cve_matches, all_assets))

        results = await asyncio.gather(*tasks)
        llm_reasoning = results[0]
        llm_prediction = results[1] if len(results) > 1 else None

        prediction = None
        if need_prediction and llm_prediction:
            prediction = self._parse_prediction(alert.attack_stage, llm_prediction, cve_matches)

        assessment = ThreatAssessment(
            alert_id=alert.id,
            overall_score=heuristic["overall_score"],
            confidence=heuristic["confidence"],
            label=heuristic["label"],
            false_positive_probability=heuristic["false_positive_probability"],
            anomaly_score=heuristic["anomaly_score"],
            threat_type=alert.threat_type,
            attack_stage=alert.attack_stage,
            reasoning=llm_reasoning,
            recommendations=self._recommendations(alert, heuristic["label"]),
            trace_summary=self._trace_summary(alert),
        )
        return AlertDetailResponse(alert=alert, assessment=assessment, prediction=prediction)

    async def build_dashboard_async(self) -> DashboardResponse:
        alerts = await self.repository.list_alerts_async()
        severity_counts = Counter(alert.severity for alert in alerts)
        status_counts = Counter(alert.status for alert in alerts)
        tactic_counts = Counter(tactic for alert in alerts for tactic in alert.mitre_tactics)
        type_counts = Counter(alert.event_type for alert in alerts)
        ticket_counts = Counter(alert.ticket.status for alert in alerts)
        assessments = [self._heuristic_scores(alert) for alert in alerts]

        online_assets = len({alert.asset.hostname for alert in alerts})
        handled_count = sum(1 for alert in alerts if alert.ticket.status in {"closed", "ignored"})
        pending_count = len(alerts) - handled_count
        high_risk = sum(1 for score in assessments if float(score["overall_score"]) >= 80)
        avg_accuracy = sum(float(score["confidence"]) for score in assessments) / max(len(alerts), 1)
        avg_response = sum(alert.ticket.response_minutes for alert in alerts) / max(len(alerts), 1)
        risk_index = sum(float(score["overall_score"]) for score in assessments) / max(len(alerts), 1)

        metrics = [
            DashboardMetric(label="实时在线资产数", value=str(online_assets), trend="基于当前告警资产统计"),
            DashboardMetric(label="今日告警总量", value=str(len(alerts)), trend="来自当前数据源实时查询"),
            DashboardMetric(label="高危告警数", value=str(high_risk), trend="需优先升级响应"),
            DashboardMetric(label="已处置 / 未处置", value=f"{handled_count} / {pending_count}", trend="待接入真实工单回写"),
            DashboardMetric(label="AI 自动研判准确率", value=f"{avg_accuracy:.0%}", trend="当前为启发式估算"),
            DashboardMetric(label="平均响应耗时", value=f"{avg_response:.0f} min", trend="当前为占位统计"),
        ]

        top_tactics = [{"name": name, "count": count} for name, count in tactic_counts.most_common(6)]
        attack_map = self._build_attack_map(alerts)
        distribution = self._build_distribution(type_counts)
        recent_records = sorted(
            [alert.ticket for alert in alerts],
            key=lambda item: item.updated_at,
            reverse=True,
        )[:6]

        return DashboardResponse(
            metrics=metrics,
            alerts_by_severity=dict(severity_counts),
            alerts_by_status=dict(status_counts),
            top_tactics=top_tactics,
            risk_gauge=RiskGauge(
                score=round(risk_index, 1),
                label="整体风险指数",
                trend="基于当前告警集合动态计算",
                ranges=[
                    GaugeRange(start=0, end=30, color="#22c55e"),
                    GaugeRange(start=31, end=70, color="#f59e0b"),
                    GaugeRange(start=71, end=100, color="#ef4444"),
                ],
            ),
            attack_map=attack_map,
            alert_type_distribution=distribution,
            ticket_flow=TicketFlowSummary(
                pending=ticket_counts.get("pending", 0),
                processing=ticket_counts.get("processing", 0),
                closed=ticket_counts.get("closed", 0),
                ignored=ticket_counts.get("ignored", 0),
                avg_response_minutes=round(avg_response, 1),
                recent_records=recent_records,
            ),
        )

    async def explain_alert_async(self, alert_id: str) -> AssessmentExplainability | None:
        alert = await self.repository.get_alert_async(alert_id)
        if not alert:
            return None

        scores = self._heuristic_scores(alert)
        components = scores.get("components", {})
        total = sum(components.values())

        feature_notes = {
            "告警严重级别": f"严重级别={alert.severity}，基础风险分值",
            "攻击阶段权重": f"当前阶段 {alert.attack_stage}，越靠后权重越高",
            "生产环境风险": f"环境={alert.asset.environment}，生产环境附加风险",
            "MITRE 战术覆盖": f"匹配 {len(alert.mitre_tactics)} 个 MITRE 战术",
            "关联实体密度": f"关联 {len(alert.related_entities)} 个实体",
            "威胁类型权重": f"威胁类型={alert.threat_type}，按危害程度加权",
        }

        rows = [
            ExplainabilityRow(
                factor=name,
                weight=round(val / total, 3) if total > 0 else 0,
                contribution=round(val, 1),
                note=feature_notes.get(name, ""),
            )
            for name, val in components.items()
        ]
        return AssessmentExplainability(
            alert_id=alert.id,
            overall_score=scores["overall_score"],
            rows=rows,
        )

    def build_dashboard(self) -> DashboardResponse:
        alerts = self.repository.list_alerts()
        severity_counts = Counter(alert.severity for alert in alerts)
        status_counts = Counter(alert.status for alert in alerts)
        tactic_counts = Counter(tactic for alert in alerts for tactic in alert.mitre_tactics)
        type_counts = Counter(alert.event_type for alert in alerts)
        ticket_counts = Counter(alert.ticket.status for alert in alerts)
        assessments = [self._heuristic_scores(alert) for alert in alerts]

        online_assets = len({alert.asset.hostname for alert in alerts})
        handled_count = sum(1 for alert in alerts if alert.ticket.status in {"closed", "ignored"})
        pending_count = len(alerts) - handled_count
        high_risk = sum(1 for score in assessments if float(score["overall_score"]) >= 80)
        avg_accuracy = sum(float(score["confidence"]) for score in assessments) / max(len(alerts), 1)
        avg_response = sum(alert.ticket.response_minutes for alert in alerts) / max(len(alerts), 1)
        risk_index = sum(float(score["overall_score"]) for score in assessments) / max(len(alerts), 1)

        metrics = [
            DashboardMetric(label="实时在线资产数", value=str(online_assets), trend="较昨日 +6"),
            DashboardMetric(label="今日告警总量", value=str(len(alerts)), trend="近 1 小时持续攀升"),
            DashboardMetric(label="高危告警数", value=str(high_risk), trend="需优先升级响应"),
            DashboardMetric(label="已处置 / 未处置", value=f"{handled_count} / {pending_count}", trend="工单闭环率稳定"),
            DashboardMetric(label="AI 自动研判准确率", value=f"{avg_accuracy:.0%}", trend="模型置信度稳中提升"),
            DashboardMetric(label="平均响应耗时", value=f"{avg_response:.0f} min", trend="较上周缩短 18%"),
        ]

        top_tactics = [{"name": name, "count": count} for name, count in tactic_counts.most_common(6)]
        attack_map = self._build_attack_map(alerts)
        distribution = self._build_distribution(type_counts)
        recent_records = sorted(
            [alert.ticket for alert in alerts],
            key=lambda item: item.updated_at,
            reverse=True,
        )[:6]

        return DashboardResponse(
            metrics=metrics,
            alerts_by_severity=dict(severity_counts),
            alerts_by_status=dict(status_counts),
            top_tactics=top_tactics,
            risk_gauge=RiskGauge(
                score=round(risk_index, 1),
                label="整体风险指数",
                trend="受高危横向移动与暴力破解事件拉升",
                ranges=[
                    GaugeRange(start=0, end=30, color="#22c55e"),
                    GaugeRange(start=31, end=70, color="#f59e0b"),
                    GaugeRange(start=71, end=100, color="#ef4444"),
                ],
            ),
            attack_map=attack_map,
            alert_type_distribution=distribution,
            ticket_flow=TicketFlowSummary(
                pending=ticket_counts.get("pending", 0),
                processing=ticket_counts.get("processing", 0),
                closed=ticket_counts.get("closed", 0),
                ignored=ticket_counts.get("ignored", 0),
                avg_response_minutes=round(avg_response, 1),
                recent_records=recent_records,
            ),
        )

    def explain_alert(self, alert_id: str) -> AssessmentExplainability | None:
        alert = self.repository.get_alert(alert_id)
        if not alert:
            return None

        scores = self._heuristic_scores(alert)
        components = scores.get("components", {})
        total = sum(components.values())

        feature_notes = {
            "告警严重级别": f"严重级别={alert.severity}，基础风险分值",
            "攻击阶段权重": f"当前阶段 {alert.attack_stage}，越靠后权重越高",
            "生产环境风险": f"环境={alert.asset.environment}，生产环境附加风险",
            "MITRE 战术覆盖": f"匹配 {len(alert.mitre_tactics)} 个 MITRE 战术",
            "关联实体密度": f"关联 {len(alert.related_entities)} 个实体",
            "威胁类型权重": f"威胁类型={alert.threat_type}，按危害程度加权",
        }

        rows = [
            ExplainabilityRow(
                factor=name,
                weight=round(val / total, 3) if total > 0 else 0,
                contribution=round(val, 1),
                note=feature_notes.get(name, ""),
            )
            for name, val in components.items()
        ]
        return AssessmentExplainability(
            alert_id=alert.id,
            overall_score=scores["overall_score"],
            rows=rows,
        )

    def _heuristic_scores(self, alert: SIEMAlert) -> dict[str, float | str]:
        severity_weight = {
            "low": 20,
            "medium": 45,
            "high": 72,
            "critical": 90,
        }[alert.severity]
        stage_bonus = {
            "Reconnaissance": 4,
            "Initial Access": 8,
            "Execution": 11,
            "Command and Control": 14,
            "Exfiltration": 16,
        }[alert.attack_stage]
        prod_bonus = 8 if alert.asset.environment == "prod" else 0
        tactic_bonus = min(len(alert.mitre_tactics) * 3, 12)
        entity_bonus = min(len(alert.related_entities) * 2, 8)
        threat_bonus = {
            "brute-force": 5,
            "miner": 4,
            "ransomware": 10,
            "c2": 12,
            "port-scan": 3,
            "exfiltration": 11,
            "web-attack": 9,
        }[alert.threat_type]
        anomaly_score = min(
            0.23
            + len(alert.timeline) * 0.07
            + len(alert.related_entities) * 0.05
            + (0.12 if "powershell" in alert.log_excerpt.lower() else 0)
            + (0.15 if "failed" in alert.log_excerpt.lower() else 0)
            + (0.10 if "tls" in alert.log_excerpt.lower() else 0),
            0.99,
        )
        raw_sum = severity_weight + stage_bonus + prod_bonus + tactic_bonus + entity_bonus + threat_bonus
        overall_score = min(raw_sum, 100)
        false_positive_probability = max(0.03, 1 - overall_score / 112 - anomaly_score / 4)
        confidence = min(0.58 + overall_score / 205 + anomaly_score / 5, 0.99)

        if overall_score >= 85:
            label = "confirmed-threat"
        elif overall_score >= 55:
            label = "suspicious"
        else:
            label = "benign"

        summary = (
            f"风险分 {overall_score:.1f}/100，异常分 {anomaly_score:.2f}，"
            f"误报概率 {false_positive_probability:.2f}，攻击阶段 {alert.attack_stage}，"
            f"威胁类型 {alert.threat_type}，分类为 {label}。"
        )

        # 归一化分项贡献：若原始和超过上限，按比例缩放使各分项之和 = overall_score
        if raw_sum > 100:
            scale = overall_score / raw_sum
            sev = round(severity_weight * scale, 1)
            stg = round(stage_bonus * scale, 1)
            prd = round(prod_bonus * scale, 1)
            tac = round(tactic_bonus * scale, 1)
            ent = round(entity_bonus * scale, 1)
            thr = round(threat_bonus * scale, 1)
        else:
            sev, stg, prd, tac, ent, thr = (
                severity_weight, stage_bonus, prod_bonus, tactic_bonus, entity_bonus, threat_bonus
            )

        components = {
            "告警严重级别": sev,
            "攻击阶段权重": stg,
            "生产环境风险": prd,
            "MITRE 战术覆盖": tac,
            "关联实体密度": ent,
            "威胁类型权重": thr,
        }

        return {
            "overall_score": round(overall_score, 2),
            "confidence": round(confidence, 2),
            "label": label,
            "false_positive_probability": round(false_positive_probability, 2),
            "anomaly_score": round(anomaly_score, 2),
            "summary": summary,
            "components": components,
        }

    def _recommendations(self, alert: SIEMAlert, label: str) -> list[str]:
        if label == "confirmed-threat":
            return [
                f"立即阻断源 IP {alert.source_ip}，在边界防火墙添加 deny 规则",
                f"隔离涉事终端 {alert.asset.hostname} ({alert.asset.ip})，禁止横向移动",
                f"重置 {alert.asset.hostname} 上受影响账号凭据，排查后门持久化",
                f"提取 IOC 同步至 SIEM/EDR，全量回溯 {alert.source_ip} 近 72h 活动",
                "启动应急响应流程，通知安全负责人并留存取证材料",
            ]
        if label == "suspicious":
            return [
                f"对源 IP {alert.source_ip} 启动定向狩猎，分析访问模式与时间线",
                f"在 {alert.asset.hostname} 部署额外审计规则，监控异常进程与网络连接",
                f"提取 IOC (IP/域名/Hash) 同步至威胁情报平台交叉验证",
                "若确认恶意行为，升级为高危事件并启动应急响应",
                "更新 SIEM 关联规则，提升对同类行为的检测灵敏度",
            ]
        return [
            f"持续监控源 IP {alert.source_ip}，观察是否重复触发类似告警",
            f"优化 {alert.rule_name} 规则阈值，降低误报率",
            f"确认 {alert.asset.hostname} 上相关服务为正常业务行为后标记为白名单",
            "沉淀本次分析结果为知识库条目，减少后续重复研判成本",
        ]

    def _trace_summary(self, alert: SIEMAlert) -> list[str]:
        return [f"{event.timestamp.isoformat()} - {event.message}" for event in alert.timeline]

    @staticmethod
    def _parse_prediction(current_stage: str, llm_response: str, cve_matches: list[dict]) -> AttackPrediction:
        """Parse LLM prediction response into structured AttackPrediction."""
        import re

        next_stage = ""
        rationale = ""
        targets: list[str] = []
        defense: list[str] = []
        risk_score = 50.0
        confidence = 0.6

        # Extract next stage
        stage_match = re.search(r"预测下一攻击阶段[：:]\s*(.+)", llm_response, re.IGNORECASE)
        if stage_match:
            stage_text = stage_match.group(1).strip()
            stage_keywords = {
                "reconnaissance": "Reconnaissance",
                "侦察": "Reconnaissance",
                "初始访问": "Initial Access",
                "initial access": "Initial Access",
                "植入": "Initial Access",
                "execution": "Execution",
                "执行": "Execution",
                "command and control": "Command and Control",
                "命令控制": "Command and Control",
                "命令与控制": "Command and Control",
                "exfiltration": "Exfiltration",
                "数据渗出": "Exfiltration",
                "渗出": "Exfiltration",
            }
            for kw, stage in stage_keywords.items():
                if kw.lower() in stage_text.lower():
                    next_stage = stage
                    break
            if not next_stage:
                next_stage = stage_text[:50]

        # Extract risk score
        score_match = re.search(r"风险评分[：:]\s*(\d+)", llm_response, re.IGNORECASE)
        if score_match:
            risk_score = min(100, max(0, int(score_match.group(1))))
            if risk_score >= 80:
                confidence = 0.85
            elif risk_score >= 60:
                confidence = 0.72
            else:
                confidence = 0.55

        # Extract attack path reasoning
        path_match = re.search(r"攻击路径推理[：:]\s*(.+?)(?:\n\d\.|$)", llm_response, re.DOTALL | re.IGNORECASE)
        if path_match:
            rationale = path_match.group(1).strip()[:500]

        # Extract high-risk targets
        target_match = re.search(r"高风险目标[：:]\s*(.+?)(?:\n\d\.|$)", llm_response, re.DOTALL | re.IGNORECASE)
        if target_match:
            targets = [t.strip("- *") for t in target_match.group(1).strip().split("\n") if t.strip()][:3]

        # Extract defense actions
        defense_match = re.search(r"建议防御动作[：:]\s*(.+?)(?:\n\d\.|$)", llm_response, re.DOTALL | re.IGNORECASE)
        if defense_match:
            defense = [d.strip("- *") for d in defense_match.group(1).strip().split("\n") if d.strip()][:3]

        # Use the LLM's full response as rationale if we didn't extract a specific section
        if not rationale:
            rationale = llm_response[:400]

        # Build attack vector summary from CVE matches
        attack_vector_parts = []
        if cve_matches:
            top_cve = cve_matches[0]
            attack_vector_parts.append(f"利用 {top_cve['id']} ({top_cve['exploit_type']})")
        if next_stage:
            attack_vector_parts.append(f"向 {next_stage} 阶段推进")
        attack_vector = " → ".join(attack_vector_parts) if attack_vector_parts else "未知"

        return AttackPrediction(
            current_stage=current_stage,
            predicted_next_stage=next_stage or "Execution",
            confidence=round(confidence, 2),
            risk_score=round(risk_score, 1),
            likely_targets=targets,
            attack_vector=attack_vector,
            rationale=rationale,
            recommended_defense=defense,
            matched_cves=cve_matches[:3],
        )

    def _build_attack_map(self, alerts: list[SIEMAlert]) -> list[GeoAttackPoint]:
        points: list[GeoAttackPoint] = []
        for index, alert in enumerate(sorted(alerts, key=lambda item: item.timestamp, reverse=True)[:24]):
            jitter_lon = ((index % 5) - 2) * 0.9
            jitter_lat = ((index % 4) - 1.5) * 0.7
            intensity = min(1.0, float(self._heuristic_scores(alert)["overall_score"]) / 100)
            attacks = max(1, int(round(intensity * 6)))
            points.append(
                GeoAttackPoint(
                    name=f"{alert.source_geo.city}-{index + 1}",
                    country=alert.source_geo.country,
                    latitude=alert.source_geo.latitude + jitter_lat,
                    longitude=alert.source_geo.longitude + jitter_lon,
                    intensity=round(max(0.25, intensity), 2),
                    attacks=attacks,
                )
            )
        return points

    def _build_distribution(self, type_counts: Counter[str]) -> list[DistributionSlice]:
        # 英文事件类型 → 中文显示名
        type_label_map = {
            "brute-force": "暴力破解",
            "port-scan": "端口扫描",
            "c2": "可疑外连",
            "ransomware": "恶意文件",
            "exfiltration": "可疑外连",
            "miner": "恶意文件",
            "web-attack": "漏洞利用",
        }
        color_map = {
            "暴力破解": "#ef4444",
            "异常登录": "#f97316",
            "端口扫描": "#38bdf8",
            "可疑外连": "#22c55e",
            "恶意文件": "#facc15",
            "漏洞利用": "#a78bfa",
            "认证日志": "#e879f9",
            "Wazuh告警": "#64748b",
            "Windows事件": "#06b6d4",
            "文件完整性监控": "#84cc16",
            "防火墙日志": "#f97316",
        }

        # 合并计数 (英文 → 中文)
        merged: Counter[str] = Counter()
        for raw_type, cnt in type_counts.items():
            label = type_label_map.get(raw_type, raw_type)
            merged[label] += cnt

        order = ["暴力破解", "异常登录", "端口扫描", "可疑外连", "恶意文件", "漏洞利用"]
        remaining = sorted([t for t in merged if t not in order])
        order += remaining

        return [
            DistributionSlice(
                name=name,
                count=merged.get(name, 0),
                color=color_map.get(name, "#38bdf8"),
            )
            for name in order
        ]
