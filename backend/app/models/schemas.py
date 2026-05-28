from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


Severity = Literal["low", "medium", "high", "critical"]
AlertStatus = Literal["new", "investigating", "resolved", "ignored", "escalated"]
ThreatLabel = Literal["benign", "suspicious", "confirmed-threat"]
ThreatType = Literal["brute-force", "miner", "ransomware", "c2", "port-scan", "exfiltration", "web-attack"]
AttackStage = Literal["Reconnaissance", "Initial Access", "Execution", "Command and Control", "Exfiltration"]


class GeoPoint(BaseModel):
    region: str
    country: str
    city: str
    latitude: float
    longitude: float


class AssetContext(BaseModel):
    hostname: str
    ip: str
    owner: str
    environment: Literal["dev", "test", "prod"]


class PacketDetails(BaseModel):
    protocol: str
    request_method: str
    request_uri: str
    source_port: int
    destination_port: int
    packet_size: int
    tcp_flags: str
    payload_preview: str


class TimelineEvent(BaseModel):
    timestamp: datetime
    message: str


class TicketRecord(BaseModel):
    status: Literal["pending", "processing", "closed", "ignored"]
    assignee: str
    updated_at: datetime
    response_minutes: int


class SimilarIncidentStats(BaseModel):
    total: int
    last_7_days: int
    closed_rate: float = Field(ge=0, le=1)


class SIEMAlert(BaseModel):
    id: str
    title: str
    source: Literal["wazuh", "elk", "suricata"]
    severity: Severity
    status: AlertStatus
    timestamp: datetime
    rule_name: str
    description: str
    log_excerpt: str
    source_ip: str
    destination_ip: str
    source_geo: GeoPoint
    event_type: str
    request_content: str
    packet_details: PacketDetails
    threat_type: ThreatType
    attack_stage: AttackStage
    related_rule_ids: list[str] = Field(default_factory=list)
    hardening_suggestions: list[str] = Field(default_factory=list)
    similar_incidents: SimilarIncidentStats
    ticket: TicketRecord
    mitre_tactics: list[str] = Field(default_factory=list)
    asset: AssetContext
    related_entities: list[str] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)


class ThreatAssessment(BaseModel):
    alert_id: str
    overall_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    label: ThreatLabel
    false_positive_probability: float = Field(ge=0, le=1)
    anomaly_score: float = Field(ge=0, le=1)
    threat_type: ThreatType
    attack_stage: AttackStage
    reasoning: str
    recommendations: list[str]
    trace_summary: list[str]


class AttackPrediction(BaseModel):
    current_stage: str
    predicted_next_stage: str
    confidence: float = Field(ge=0, le=1)
    risk_score: float = Field(ge=0, le=100)
    likely_targets: list[str] = Field(default_factory=list)
    attack_vector: str = ""
    rationale: str = ""
    recommended_defense: list[str] = Field(default_factory=list)
    matched_cves: list[dict] = Field(default_factory=list)


class AlertDetailResponse(BaseModel):
    alert: SIEMAlert
    assessment: ThreatAssessment
    prediction: AttackPrediction | None = None


class DashboardMetric(BaseModel):
    label: str
    value: str
    trend: str


class GaugeRange(BaseModel):
    start: int
    end: int
    color: str


class RiskGauge(BaseModel):
    score: float = Field(ge=0, le=100)
    label: str
    trend: str
    ranges: list[GaugeRange]


class GeoAttackPoint(BaseModel):
    name: str
    country: str
    latitude: float
    longitude: float
    intensity: float = Field(ge=0, le=1)
    attacks: int


class DistributionSlice(BaseModel):
    name: str
    count: int
    color: str


class TicketFlowSummary(BaseModel):
    pending: int
    processing: int
    closed: int
    ignored: int
    avg_response_minutes: float
    recent_records: list[TicketRecord]


class DashboardResponse(BaseModel):
    metrics: list[DashboardMetric]
    alerts_by_severity: dict[str, int]
    alerts_by_status: dict[str, int]
    top_tactics: list[dict[str, int | str]]
    risk_gauge: RiskGauge
    attack_map: list[GeoAttackPoint]
    alert_type_distribution: list[DistributionSlice]
    ticket_flow: TicketFlowSummary


class AnalyzeRequest(BaseModel):
    alert_id: str


class ExplainabilityRow(BaseModel):
    factor: str
    weight: float
    note: str


class AssessmentExplainability(BaseModel):
    alert_id: str
    rows: list[ExplainabilityRow]


class StatusUpdateRequest(BaseModel):
    status: AlertStatus


class PagedAlertsResponse(BaseModel):
    items: list[SIEMAlert]
    total: int
    page: int
    size: int
    total_pages: int


class KeyAlert(BaseModel):
    id: str
    title: str
    severity: str


class IncidentItem(BaseModel):
    source_ip: str
    count: int
    severities: dict[str, int] = {}
    latest: str = ""
    location: str = ""
    key_alerts: list[KeyAlert] = []


class IncidentsResponse(BaseModel):
    incidents: list[IncidentItem]
    total_ips: int
    total_alerts: int
