<script setup lang="ts">
import { ref } from "vue";
import type { ActionStatus, Alert, AlertDetail } from "../api/client";
import { fetchNarrative, updateAlertStatus } from "../api/client";
import { highlightLog, renderMarkdown } from "../utils/markdown";

const props = defineProps<{
  detail: AlertDetail | null;
  selectedAlert: Alert | null;
  loading: boolean;
}>();

const emit = defineEmits<{
  (e: "status-changed"): void;
}>();

const acting = ref(false);
const actionMsg = ref("");

// Narrative
const showNarrative = ref(false);
const narrativeLoading = ref(false);
const narrativeText = ref("");

async function generateNarrative() {
  if (!props.selectedAlert) return;
  narrativeLoading.value = true;
  narrativeText.value = "";
  showNarrative.value = true;
  try {
    const res = await fetchNarrative(props.selectedAlert.id);
    narrativeText.value = res.narrative;
  } catch {
    narrativeText.value = "报告生成失败，请重试。";
  } finally {
    narrativeLoading.value = false;
  }
}

async function handleStatus(status: ActionStatus) {
  if (!props.selectedAlert) return;
  acting.value = true;
  actionMsg.value = "";
  try {
    await updateAlertStatus(props.selectedAlert.id, status);
    const labels: Record<ActionStatus, string> = {
      resolved: "已处置",
      ignored: "已忽略",
      escalated: "已升级",
    };
    actionMsg.value = `告警 ${labels[status]}`;
    emit("status-changed");
  } catch {
    actionMsg.value = "操作失败";
  } finally {
    acting.value = false;
  }
}

const stages = [
  "Reconnaissance", "Initial Access", "Execution",
  "Command and Control", "Privilege Escalation",
  "Lateral Movement", "Credential Access", "Exfiltration", "Impact",
];

const stageLabels: Record<string, string> = {
  Reconnaissance: "侦察", "Initial Access": "植入",
  Execution: "执行", "Command and Control": "命令控制",
  "Privilege Escalation": "权限提升", "Lateral Movement": "横向移动",
  "Credential Access": "凭据窃取", Exfiltration: "数据渗出", Impact: "影响破坏",
};

const threatLabels: Record<string, string> = {
  "brute-force": "暴力破解", miner: "挖矿活动", ransomware: "勒索行为",
  c2: "C2 控制", "port-scan": "端口扫描", exfiltration: "数据渗出",
  "web-attack": "Web攻击", "sql-injection": "SQL注入", xss: "XSS跨站脚本",
  phishing: "钓鱼攻击", ddos: "DDoS拒绝服务", webshell: "Webshell上传",
  "privilege-escalation": "权限提升", "lateral-movement": "横向移动",
  "credential-dumping": "凭据转储",
};

function getThreatLabel(threatType?: string) {
  if (!threatType) return "待判定";
  return threatLabels[threatType] ?? threatType;
}

function getText(value?: string) {
  return value && value.trim() ? value : "暂无数据";
}

function getStageLabel(stage: string) {
  return stageLabels[stage] ?? stage;
}

function cveSeverityColor(severity: string) {
  return severity === "critical" ? "#ef4444" : severity === "high" ? "#f97316" : "#facc15";
}
</script>

<template>
  <section class="panel panel-accent-blue analysis-panel">
    <div class="panel-heading">
      <h2>AI 智能研判大屏</h2>
      <span class="panel-tag">LLM Intelligence Core</span>
    </div>

    <div v-if="loading && !detail" class="empty-state">正在分析告警上下文...</div>
    <div v-else-if="detail && selectedAlert" class="analysis-layout">
      <div class="analysis-top">
        <article class="analysis-card log-card">
          <div class="sub-heading">
            <span>原始日志</span>
            <span>{{ selectedAlert.rule_name }}</span>
          </div>
          <pre class="log-block" v-html="highlightLog(selectedAlert.log_excerpt)"></pre>
        </article>

        <article class="analysis-card summary-card">
          <div class="sub-heading">
            <span>AI 自动分析结论</span>
            <span>{{ getThreatLabel(detail.assessment.threat_type) }}</span>
          </div>
          <div class="markdown-body" v-html="renderMarkdown(detail.assessment.reasoning)"></div>
        </article>
      </div>

      <div class="analysis-stats">
        <article class="mini-stat">
          <span>威胁类型</span>
          <strong>{{ getThreatLabel(detail.assessment.threat_type) }}</strong>
        </article>
        <article class="mini-stat">
          <span>误报概率</span>
          <strong>{{ Math.round(detail.assessment.false_positive_probability * 100) }}%</strong>
        </article>
        <article class="mini-stat">
          <span>置信度评分</span>
          <strong>{{ Math.round(detail.assessment.confidence * 100) }}</strong>
        </article>
      </div>

      <div class="action-bar">
        <button class="action-btn action-resolve" :disabled="acting" @click="handleStatus('resolved')">
          标记已处置
        </button>
        <button class="action-btn action-ignore" :disabled="acting" @click="handleStatus('ignored')">
          忽略误报
        </button>
        <button class="action-btn action-escalate" :disabled="acting" @click="handleStatus('escalated')">
          升级工单
        </button>
        <button class="action-btn action-narrative" :disabled="acting" @click="generateNarrative">
          📄 生成事件报告
        </button>
        <span v-if="actionMsg" class="action-msg">{{ actionMsg }}</span>
      </div>

      <article class="analysis-card attack-chain-card">
        <div class="sub-heading">
          <span>攻击链阶段</span>
          <span>Kill Chain</span>
        </div>
        <div class="chain-track">
          <div
            v-for="stage in stages"
            :key="stage"
            class="chain-node"
            :class="{ active: detail.assessment.attack_stage === stage, predicted: detail.prediction?.predicted_next_stage === stage }"
          >
            <span>{{ stageLabels[stage] }}</span>
            <small>{{ stage }}</small>
          </div>
        </div>
      </article>

      <!-- Attack Prediction -->
      <article v-if="detail.prediction" class="analysis-card prediction-card">
        <div class="sub-heading">
          <span>攻击路径推演</span>
          <span class="prediction-badge">AI 预测</span>
        </div>

        <div class="prediction-grid">
          <div class="pred-item pred-next">
            <span class="pred-label">预测下一阶段</span>
            <strong class="pred-value stage-highlight">
              {{ getStageLabel(detail.prediction.predicted_next_stage) }}
            </strong>
            <small>{{ detail.prediction.current_stage }} → {{ detail.prediction.predicted_next_stage }}</small>
          </div>
          <div class="pred-item pred-risk">
            <span class="pred-label">入侵风险评分</span>
            <strong class="pred-value risk-score" :class="detail.prediction.risk_score >= 70 ? 'risk-high' : 'risk-mid'">
              {{ detail.prediction.risk_score }}
            </strong>
            <small>置信度 {{ Math.round(detail.prediction.confidence * 100) }}%</small>
          </div>
          <div class="pred-item pred-vector">
            <span class="pred-label">攻击路径</span>
            <strong class="pred-value">{{ detail.prediction.attack_vector || "推演中..." }}</strong>
          </div>
        </div>

        <div v-if="detail.prediction.rationale" class="pred-rationale markdown-body" v-html="renderMarkdown(detail.prediction.rationale)"></div>

        <div v-if="detail.prediction.matched_cves.length" class="cve-section">
          <span class="cve-title">关联高危 CVE</span>
          <div class="cve-list">
            <div v-for="cve in detail.prediction.matched_cves" :key="cve.id" class="cve-chip">
              <span class="cve-badge" :style="{ background: cveSeverityColor(cve.severity) }">{{ cve.severity.toUpperCase() }}</span>
              <span class="cve-id">{{ cve.id }}</span>
              <span class="cve-score">CVSS {{ cve.cvss }}</span>
              <span class="cve-desc">{{ cve.description.slice(0, 60) }}...</span>
            </div>
          </div>
        </div>

        <div v-if="detail.prediction.recommended_defense.length" class="defense-section">
          <span class="defense-title">防御建议</span>
          <ul class="defense-list">
            <li v-for="(d, i) in detail.prediction.recommended_defense" :key="i">{{ d }}</li>
          </ul>
        </div>
      </article>
    </div>
    <div v-else class="empty-state">等待选中告警后展示 AI 研判结果。</div>

    <!-- Narrative Modal -->
    <Teleport to="body">
      <div v-if="showNarrative" class="modal-backdrop" @click.self="showNarrative = false">
        <div class="modal-panel narrative-modal">
          <div class="modal-header">
            <h3>攻击事件分析报告</h3>
            <button class="modal-close" @click="showNarrative = false">✕</button>
          </div>
          <div class="modal-body">
            <div v-if="narrativeLoading" class="empty-state">AI 正在生成攻击事件报告...</div>
            <div v-else class="markdown-body" v-html="renderMarkdown(narrativeText)"></div>
          </div>
        </div>
      </div>
    </Teleport>
  </section>
</template>
