import axios from "axios";
import { getToken } from "../auth";

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "/api",
  timeout: 20000,
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("soc-jwt-token");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  },
);

export type Severity = "low" | "medium" | "high" | "critical";
export type Status = "new" | "investigating" | "resolved";
export type ThreatType =
  | "brute-force"
  | "miner"
  | "ransomware"
  | "c2"
  | "port-scan"
  | "exfiltration";
export type AttackStage =
  | "Reconnaissance"
  | "Initial Access"
  | "Execution"
  | "Command and Control"
  | "Exfiltration";

export interface TicketRecord {
  status: "pending" | "processing" | "closed" | "ignored";
  assignee: string;
  updated_at: string;
  response_minutes: number;
}

export interface PacketDetails {
  protocol: string;
  request_method: string;
  request_uri: string;
  source_port: number;
  destination_port: number;
  packet_size: number;
  tcp_flags: string;
  payload_preview: string;
}

export interface Alert {
  id: string;
  title: string;
  source: "wazuh" | "elk" | "suricata";
  severity: Severity;
  status: Status;
  timestamp: string;
  rule_name: string;
  description: string;
  log_excerpt: string;
  source_ip: string;
  destination_ip: string;
  source_geo: {
    region: string;
    country: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  event_type: string;
  request_content: string;
  packet_details: PacketDetails;
  threat_type: ThreatType;
  attack_stage: AttackStage;
  related_rule_ids: string[];
  hardening_suggestions: string[];
  similar_incidents: {
    total: number;
    last_7_days: number;
    closed_rate: number;
  };
  ticket: TicketRecord;
  mitre_tactics: string[];
  related_entities: string[];
  asset: {
    hostname: string;
    ip: string;
    owner: string;
    environment: "dev" | "test" | "prod";
  };
  timeline: Array<{ timestamp: string; message: string }>;
}

export interface DashboardMetric {
  label: string;
  value: string;
  trend: string;
}

export interface DashboardData {
  metrics: DashboardMetric[];
  alerts_by_severity: Record<string, number>;
  alerts_by_status: Record<string, number>;
  top_tactics: Array<{ name: string; count: number }>;
  risk_gauge: {
    score: number;
    label: string;
    trend: string;
    ranges: Array<{ start: number; end: number; color: string }>;
  };
  attack_map: Array<{
    name: string;
    country: string;
    latitude: number;
    longitude: number;
    intensity: number;
    attacks: number;
  }>;
  alert_type_distribution: Array<{ name: string; count: number; color: string }>;
  ticket_flow: {
    pending: number;
    processing: number;
    closed: number;
    ignored: number;
    avg_response_minutes: number;
    recent_records: TicketRecord[];
  };
}

export interface AlertDetail {
  alert: Alert;
  assessment: {
    alert_id: string;
    overall_score: number;
    confidence: number;
    label: "benign" | "suspicious" | "confirmed-threat";
    false_positive_probability: number;
    anomaly_score: number;
    reasoning: string;
    recommendations: string[];
    trace_summary: string[];
    threat_type: ThreatType;
    attack_stage: AttackStage;
  };
}

export interface Explainability {
  alert_id: string;
  rows: Array<{ factor: string; weight: number; note: string }>;
}

export async function fetchDashboard() {
  const { data } = await api.get<DashboardData>("/dashboard");
  return data;
}

export interface PagedAlerts {
  items: Alert[];
  total: number;
  page: number;
  size: number;
  total_pages: number;
}

export async function fetchAlerts(page = 1, size = 20) {
  const { data } = await api.get<PagedAlerts>("/alerts", { params: { page, size } });
  return data;
}

export async function fetchAlertDetail(alertId: string) {
  const { data } = await api.get<AlertDetail>(`/alerts/${alertId}`);
  return data;
}

export async function fetchExplainability(alertId: string) {
  const { data } = await api.get<Explainability>(`/alerts/${alertId}/explainability`);
  return data;
}

export interface WazuhHealth {
  indexer: { ok: boolean; url: string; cluster_status?: string; circuit_breaker: string };
  manager: { ok: boolean; url: string; version?: string; circuit_breaker: string };
  overall: string;
}

export interface WazuhAgent {
  id: string;
  name: string;
  ip: string;
  status: string;
  os?: { name?: string; version?: string };
}

export async function fetchWazuhHealth() {
  const { data } = await api.get<WazuhHealth>("/health/wazuh");
  return data;
}

export async function fetchWazuhAgents() {
  const { data } = await api.get<WazuhAgent[]>("/agents");
  return data;
}

export type ActionStatus = "resolved" | "ignored" | "escalated";

export async function updateAlertStatus(alertId: string, status: ActionStatus) {
  const { data } = await api.patch<Alert>(`/alerts/${alertId}/status`, { status });
  return data;
}

export interface KeyAlert {
  id: string;
  title: string;
  severity: string;
}

export interface IncidentItem {
  source_ip: string;
  count: number;
  severities: Record<string, number>;
  latest: string;
  location: string;
  key_alerts: KeyAlert[];
}

export interface IncidentsResponse {
  incidents: IncidentItem[];
  total_ips: number;
  total_alerts: number;
}

export async function fetchIncidents(top = 10) {
  const { data } = await api.get<IncidentsResponse>("/incidents", { params: { top } });
  return data;
}
