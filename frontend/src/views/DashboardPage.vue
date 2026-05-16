<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import AiAnalysisBoard from "../components/AiAnalysisBoard.vue";
import AlertFlowTicker from "../components/AlertFlowTicker.vue";
import CockpitHeader from "../components/CockpitHeader.vue";
import ExplainabilityPanel from "../components/ExplainabilityPanel.vue";
import ResponseAdvicePanel from "../components/ResponseAdvicePanel.vue";
import SituationVisualizationPanel from "../components/SituationVisualizationPanel.vue";
import TicketFlowPanel from "../components/TicketFlowPanel.vue";
import {
  type Alert,
  type AlertDetail,
  type DashboardData,
  type Explainability,
  fetchAlertDetail,
  fetchAlerts,
  fetchDashboard,
  fetchExplainability,
} from "../api/client";
import { clearAuth } from "../auth";

const router = useRouter();
const alerts = ref<Alert[]>([]);
const dashboard = ref<DashboardData | null>(null);
const selectedAlertId = ref("");
const detail = ref<AlertDetail | null>(null);
const explainability = ref<Explainability | null>(null);
const loading = ref(false);
const isFullscreen = ref(false);
let rotateTimer: number | undefined;

const selectedAlert = computed(() => alerts.value.find((item) => item.id === selectedAlertId.value) ?? null);

async function loadInitialData() {
  loading.value = true;
  try {
    const [dashboardData, alertData] = await Promise.all([fetchDashboard(), fetchAlerts()]);
    dashboard.value = dashboardData;
    alerts.value = alertData;
    selectedAlertId.value = alertData[0]?.id ?? "";
  } finally {
    loading.value = false;
  }
}

async function loadAlertContext(alertId: string) {
  loading.value = true;
  try {
    const [detailData, explainData] = await Promise.all([
      fetchAlertDetail(alertId),
      fetchExplainability(alertId),
    ]);
    detail.value = detailData;
    explainability.value = explainData;
  } finally {
    loading.value = false;
  }
}

function startRotation() {
  stopRotation();
  rotateTimer = window.setInterval(() => {
    if (!alerts.value.length) return;
    const currentIndex = alerts.value.findIndex((item) => item.id === selectedAlertId.value);
    const nextIndex = currentIndex >= 0 ? (currentIndex + 1) % alerts.value.length : 0;
    selectedAlertId.value = alerts.value[nextIndex].id;
  }, 6000);
}

function stopRotation() {
  if (rotateTimer) {
    window.clearInterval(rotateTimer);
    rotateTimer = undefined;
  }
}

async function toggleFullscreen() {
  if (!document.fullscreenElement) {
    await document.documentElement.requestFullscreen();
    isFullscreen.value = true;
    return;
  }
  await document.exitFullscreen();
  isFullscreen.value = false;
}

function logout() {
  clearAuth();
  router.push("/login");
}

watch(selectedAlertId, (alertId) => {
  if (alertId) {
    void loadAlertContext(alertId);
  }
});

onMounted(async () => {
  await loadInitialData();
  startRotation();
});

onBeforeUnmount(stopRotation);
</script>

<template>
  <div class="page-shell">
    <div class="grid-overlay"></div>
    <div class="ambient ambient-one"></div>
    <div class="ambient ambient-two"></div>
    <div class="ambient ambient-three"></div>

    <main class="dashboard-layout">
      <section class="hero-bar">
        <div>
          <p class="eyebrow">AI-Driven Advanced Threat Detection</p>
          <h1>龙王守护者-基于LLM的SIME告警智能分析平台</h1>
          <p class="hero-copy">
            以 SIEM 日志为底座，结合机器学习与大语言模型完成实时告警聚合、威胁研判、处置建议和工单闭环。
          </p>
        </div>
        <div class="hero-actions">
          <div class="hero-status">
            <span class="status-dot"></span>
            <span>LLM 分析链路在线</span>
          </div>
          <button class="hero-button" @click="toggleFullscreen">
            {{ isFullscreen ? "退出全屏" : "全屏展示" }}
          </button>
          <button class="hero-button hero-button-ghost" @click="logout">退出登录</button>
        </div>
      </section>

      <CockpitHeader :dashboard="dashboard" />

      <section class="board-grid">
        <div class="grid-card area-visual">
          <SituationVisualizationPanel :dashboard="dashboard" />
        </div>
        <div class="grid-card area-analysis">
          <AiAnalysisBoard :detail="detail" :selected-alert="selectedAlert" :loading="loading" />
        </div>
        <div class="grid-card area-alerts">
          <AlertFlowTicker
            :alerts="alerts"
            :selected-alert-id="selectedAlertId"
            :show-link-button="true"
            @select="selectedAlertId = $event"
          />
        </div>
        <div class="grid-card area-response">
          <ResponseAdvicePanel :detail="detail" :loading="loading" />
        </div>
        <div class="grid-card area-explain">
          <ExplainabilityPanel :explainability="explainability" :loading="loading" />
        </div>
        <div class="grid-card area-ticket">
          <TicketFlowPanel :dashboard="dashboard" />
        </div>
      </section>
    </main>
  </div>
</template>
