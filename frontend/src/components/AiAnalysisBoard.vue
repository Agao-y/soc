<script setup lang="ts">
import { ref } from "vue";
import type { ActionStatus, Alert, AlertDetail } from "../api/client";
import { updateAlertStatus } from "../api/client";
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
  "Reconnaissance",
  "Initial Access",
  "Execution",
  "Command and Control",
  "Exfiltration",
];

const stageLabels: Record<string, string> = {
  Reconnaissance: "侦察",
  "Initial Access": "植入",
  Execution: "执行",
  "Command and Control": "命令控制",
  Exfiltration: "数据渗出",
};

const threatLabels: Record<string, string> = {
  "brute-force": "暴力破解",
  miner: "挖矿活动",
  ransomware: "勒索行为",
  c2: "C2 控制",
  "port-scan": "端口扫描",
  exfiltration: "数据渗出",
  "web-attack": "Web攻击",
};

function getThreatLabel(threatType?: string) {
  if (!threatType) return "待判定";
  return threatLabels[threatType] ?? threatType;
}

function getText(value?: string) {
  return value && value.trim() ? value : "暂无数据";
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
            :class="{ active: detail.assessment.attack_stage === stage }"
          >
            <span>{{ stageLabels[stage] }}</span>
            <small>{{ stage }}</small>
          </div>
        </div>
      </article>
    </div>
    <div v-else class="empty-state">等待选中告警后展示 AI 研判结果。</div>
  </section>
</template>
