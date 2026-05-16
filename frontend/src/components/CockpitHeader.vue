<script setup lang="ts">
import { computed } from "vue";
import type { DashboardData } from "../api/client";

const props = defineProps<{
  dashboard: DashboardData | null;
}>();

const gauge = computed(() => props.dashboard?.risk_gauge);
const circumference = 2 * Math.PI * 82;
const progress = computed(() => {
  const score = gauge.value?.score ?? 0;
  return circumference - (score / 100) * circumference;
});
</script>

<template>
  <section class="panel panel-accent-cyan cockpit-panel">
    <div class="panel-heading">
      <h2>全局态势驾驶舱</h2>
      <span class="panel-tag">Global Situation Awareness</span>
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
