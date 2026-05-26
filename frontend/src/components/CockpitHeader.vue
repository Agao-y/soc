<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import type { DashboardData, WazuhHealth } from "../api/client";
import { fetchWazuhHealth } from "../api/client";

const props = defineProps<{
  dashboard: DashboardData | null;
}>();

const gauge = computed(() => props.dashboard?.risk_gauge);
const circumference = 2 * Math.PI * 82;
const progress = computed(() => {
  const score = gauge.value?.score ?? 0;
  return circumference - (score / 100) * circumference;
});

// Wazuh 连接状态
const wazuhHealth = ref<WazuhHealth | null>(null);
let healthTimer: number | undefined;

const wazuhStatus = computed(() => {
  if (!wazuhHealth.value) return { color: "#6b7280", label: "检测中", detail: "" };
  const { overall, indexer, manager } = wazuhHealth.value;
  if (overall === "demo_mode") return { color: "#3b82f6", label: "Demo", detail: "演示模式" };
  if (overall === "healthy") return { color: "#22c55e", label: "在线", detail: `Indexer: ${indexer.cluster_status || "ok"} / Manager: ${manager.version || "ok"}` };
  if (overall === "degraded") return { color: "#f59e0b", label: "部分降级", detail: `Indexer: ${indexer.ok ? "✓" : "✗"} Manager: ${manager.ok ? "✓" : "✗"}` };
  return { color: "#ef4444", label: "离线", detail: `Indexer: ${indexer.url} 不可达` };
});

async function refreshHealth() {
  try {
    wazuhHealth.value = await fetchWazuhHealth();
  } catch {
    wazuhHealth.value = null;
  }
}

onMounted(() => {
  refreshHealth();
  healthTimer = window.setInterval(refreshHealth, 30000);
});

onBeforeUnmount(() => {
  if (healthTimer) window.clearInterval(healthTimer);
});
</script>

<template>
  <section class="panel panel-accent-cyan cockpit-panel">
    <div class="panel-heading">
      <h2>全局态势驾驶舱</h2>
      <span class="panel-tag">Global Situation Awareness</span>
      <div class="wazuh-status" :title="wazuhStatus.detail">
        <span class="status-dot" :style="{ background: wazuhStatus.color }"></span>
        <span class="status-label">Wazuh {{ wazuhStatus.label }}</span>
      </div>
    </div>

    <div class="cockpit-grid">
      <div class="metrics-grid">
        <article v-for="metric in dashboard?.metrics ?? []" :key="metric.label" class="metric-card">
          <span class="metric-label">{{ metric.label }}</span>
          <strong class="metric-value">{{ metric.value }}</strong>
          <small class="metric-trend">{{ metric.trend }}</small>
        </article>
      </div>

      <div class="gauge-card">
        <div class="gauge-wrap">
          <svg viewBox="0 0 220 220" class="gauge-svg">
            <circle cx="110" cy="110" r="82" class="gauge-track" />
            <circle
              cx="110"
              cy="110"
              r="82"
              class="gauge-progress"
              :stroke-dasharray="circumference"
              :stroke-dashoffset="progress"
            />
          </svg>
          <div class="gauge-center">
            <span class="gauge-label">{{ gauge?.label ?? "风险指数" }}</span>
            <strong>{{ gauge?.score ?? 0 }}</strong>
            <small>{{ gauge?.trend ?? "等待数据" }}</small>
          </div>
        </div>
        <div class="gauge-legend">
          <span v-for="item in gauge?.ranges ?? []" :key="item.color" class="legend-item">
            <i :style="{ background: item.color }"></i>
            {{ item.start }}-{{ item.end }}
          </span>
        </div>
      </div>
    </div>
  </section>
</template>
