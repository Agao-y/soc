<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { type ActionStatus, type Alert, type AlertDetail, fetchAlertDetail, fetchAlerts, updateAlertStatus } from "../api/client";
import { highlightLog, renderMarkdown } from "../utils/markdown";

const router = useRouter();
const alerts = ref<Alert[]>([]);
const selectedAlertId = ref("");
const detail = ref<AlertDetail | null>(null);
const loading = ref(false);
const page = ref(1);
const totalPages = ref(1);
const acting = ref(false);
const actionMsg = ref("");
let pollTimer: number | undefined;

const selectedAlert = computed(() => alerts.value.find((item) => item.id === selectedAlertId.value) ?? null);

const threatLabels: Record<string, string> = {
  "brute-force": "暴力破解", miner: "挖矿活动", ransomware: "勒索行为",
  c2: "C2 控制", "port-scan": "端口扫描", exfiltration: "数据渗出",
};

function getText(value?: string) {
  return value && value.trim() ? value : "暂无数据";
}

function getThreatLabel(t: string) {
  return threatLabels[t] ?? t;
}

async function loadAlerts() {
  loading.value = true;
  try {
    const alertData = await fetchAlerts(page.value, 20);
    alerts.value = alertData.items;
    totalPages.value = alertData.total_pages;
    if (!alertData.items.find((a) => a.id === selectedAlertId.value)) {
      selectedAlertId.value = alertData.items[0]?.id ?? "";
    }
  } finally {
    loading.value = false;
  }
}

async function loadDetail(alertId: string) {
  detail.value = null;        // 立即清空旧数据
  loading.value = true;
  try {
    detail.value = await fetchAlertDetail(alertId);
  } catch {
    detail.value = null;
  } finally {
    loading.value = false;
  }
}

async function handleStatus(status: ActionStatus) {
  if (!selectedAlert.value) return;
  acting.value = true;
  actionMsg.value = "";
  try {
    await updateAlertStatus(selectedAlert.value.id, status);
    const labels: Record<ActionStatus, string> = { resolved: "已处置", ignored: "已忽略", escalated: "已升级" };
    actionMsg.value = `告警 ${labels[status]}`;
    await loadAlerts();
    await loadDetail(selectedAlertId.value);
  } catch {
    actionMsg.value = "操作失败";
  } finally {
    acting.value = false;
  }
}

async function goPage(p: number) {
  if (p < 1 || p > totalPages.value || p === page.value) return;
  page.value = p;
  await loadAlerts();
}

watch(selectedAlertId, (alertId) => {
  if (alertId) { void loadDetail(alertId); }
});

onMounted(() => { loadAlerts(); pollTimer = window.setInterval(loadAlerts, 30000); });
onBeforeUnmount(() => { if (pollTimer) window.clearInterval(pollTimer); });
</script>

<template>
  <div class="page-shell page-shell-centered">
    <div class="grid-overlay"></div>
    <div class="ambient ambient-one"></div>
    <div class="ambient ambient-two"></div>
    <main class="analysis-page-layout">
      <section class="hero-bar hero-bar-centered">
        <div>
          <p class="eyebrow">深度告警分析</p>
          <h1>实时告警流分析</h1>
          <p class="hero-copy analysis-copy">
            聚焦单条安全告警的源地址、目的地址、请求内容、报文细节、AI 研判结论与处置建议。
          </p>
        </div>
        <button class="hero-button" @click="router.push('/')">返回主页</button>
      </section>

      <section class="alert-analysis-grid">
        <section class="panel panel-accent-cyan centered-panel">
          <div class="panel-heading">
            <h2>实时告警流</h2>
            <span class="panel-tag">{{ alerts.length }} 条</span>
          </div>
          <div class="detail-list">
            <button
              v-for="alert in alerts"
              :key="alert.id"
              class="ticker-card"
              :class="{
                active: selectedAlertId === alert.id,
                'severity-critical': alert.severity === 'critical',
                'severity-high': alert.severity === 'high',
                'severity-medium': alert.severity === 'medium',
                'severity-low': alert.severity === 'low',
              }"
              @click="selectedAlertId = alert.id"
            >
              <div class="ticker-topline">
                <span>{{ new Date(alert.timestamp).toLocaleString('zh-CN', { hour12: false }) }}</span>
                <span>{{ alert.source_ip }}</span>
              </div>
              <strong>{{ alert.title }}</strong>
              <div class="ticker-bottomline">
                <span>{{ alert.destination_ip }}</span>
                <span>{{ alert.event_type }}</span>
              </div>
            </button>
            <div class="pager">
              <button class="pager-btn" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
              <span class="pager-info">{{ page }} / {{ totalPages }}</span>
              <button class="pager-btn" :disabled="page >= totalPages" @click="goPage(page + 1)">下一页</button>
            </div>
          </div>
        </section>

        <section class="detail-column">
          <section class="panel panel-accent-blue centered-panel">
            <div class="panel-heading">
              <h2>告警流量详情</h2>
              <span class="panel-tag">{{ selectedAlert?.rule_name ?? '等待选择' }}</span>
            </div>
            <div v-if="detail && selectedAlert" class="stack-list">
              <article class="info-card">
                <h3>连接信息</h3>
                <div class="detail-kv-grid">
                  <div><span>源 IP</span><strong>{{ detail.alert.source_ip }}</strong></div>
                  <div><span>目的 IP</span><strong>{{ detail.alert.destination_ip }}</strong></div>
                  <div><span>协议</span><strong>{{ getText(detail.alert.packet_details.protocol) }}</strong></div>
                  <div><span>攻击类型</span><strong>{{ getThreatLabel(detail.assessment.threat_type) }}</strong></div>
                </div>
              </article>

              <article class="info-card">
                <h3>请求内容</h3>
                <pre class="log-block" v-html="highlightLog(detail.alert.request_content)"></pre>
              </article>

              <article class="info-card">
                <h3>请求包详情</h3>
                <div class="detail-kv-grid">
                  <div><span>方法</span><strong>{{ getText(detail.alert.packet_details.request_method) }}</strong></div>
                  <div><span>URI</span><strong>{{ getText(detail.alert.packet_details.request_uri) }}</strong></div>
                  <div><span>源端口</span><strong>{{ detail.alert.packet_details.source_port }}</strong></div>
                  <div><span>目的端口</span><strong>{{ detail.alert.packet_details.destination_port }}</strong></div>
                  <div><span>包大小</span><strong>{{ detail.alert.packet_details.packet_size }} bytes</strong></div>
                  <div><span>TCP Flags</span><strong>{{ getText(detail.alert.packet_details.tcp_flags) }}</strong></div>
                </div>
                <pre class="log-block packet-preview" v-html="highlightLog(detail.alert.packet_details.payload_preview)"></pre>
              </article>
            </div>
            <div v-else class="empty-state">请选择一条告警查看流量详情。</div>
          </section>

          <section class="analysis-double-grid">
            <section class="panel panel-accent-blue centered-panel">
              <div class="panel-heading">
                <h2>AI 分析</h2>
                <span class="panel-tag">智能研判</span>
              </div>
              <div v-if="detail" class="stack-list">
                <article class="info-card">
                  <h3>分析结论</h3>
                  <div class="markdown-body" v-html="renderMarkdown(detail.assessment.reasoning)"></div>
                </article>
                <article class="info-card compact-card">
                  <h3>风险画像</h3>
                  <div class="stats-inline">
                    <span>风险分 {{ detail.assessment.overall_score }}</span>
                    <span>置信度 {{ Math.round(detail.assessment.confidence * 100) }}%</span>
                    <span>误报概率 {{ Math.round(detail.assessment.false_positive_probability * 100) }}%</span>
                  </div>
                </article>
                <div class="action-bar">
                  <button class="action-btn action-resolve" :disabled="acting" @click="handleStatus('resolved')">标记已处置</button>
                  <button class="action-btn action-ignore" :disabled="acting" @click="handleStatus('ignored')">忽略误报</button>
                  <button class="action-btn action-escalate" :disabled="acting" @click="handleStatus('escalated')">升级工单</button>
                  <span v-if="actionMsg" class="action-msg">{{ actionMsg }}</span>
                </div>
              </div>
            </section>

            <section class="panel panel-accent-emerald centered-panel">
              <div class="panel-heading">
                <h2>AI 处置建议</h2>
                <span class="panel-tag">处置建议</span>
              </div>
              <div v-if="detail" class="stack-list">
                <article class="info-card">
                  <h3>推荐动作</h3>
                  <ol class="ordered-list">
                    <li v-for="item in detail.assessment.recommendations" :key="item">{{ item }}</li>
                  </ol>
                </article>
                <article class="info-card compact-card">
                  <h3>加固建议</h3>
                  <ul class="plain-list">
                    <li v-for="item in detail.alert.hardening_suggestions" :key="item">{{ item }}</li>
                  </ul>
                </article>
              </div>
            </section>
          </section>
        </section>
      </section>
    </main>
  </div>
</template>
