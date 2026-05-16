<script setup lang="ts">
import type { DashboardData } from "../api/client";

defineProps<{
  dashboard: DashboardData | null;
}>();
</script>

<template>
  <section class="panel">
    <div class="section-title-row">
      <h2>安全态势总览</h2>
      <span class="pill">LLM + ML + SIEM</span>
    </div>

    <div v-if="dashboard" class="metric-grid">
      <article v-for="metric in dashboard.metrics" :key="metric.label" class="metric-card">
        <span class="metric-label">{{ metric.label }}</span>
        <strong class="metric-value">{{ metric.value }}</strong>
        <small class="metric-trend">{{ metric.trend }}</small>
      </article>
    </div>

    <div v-if="dashboard" class="chart-grid">
      <div class="chart-card">
        <h3>按严重级别分布</h3>
        <div class="tag-wrap">
          <span v-for="(count, severity) in dashboard.alerts_by_severity" :key="severity" class="tag">
            {{ severity }} / {{ count }}
          </span>
        </div>
      </div>
      <div class="chart-card">
        <h3>按状态分布</h3>
        <div class="tag-wrap">
          <span v-for="(count, status) in dashboard.alerts_by_status" :key="status" class="tag">
            {{ status }} / {{ count }}
          </span>
        </div>
      </div>
      <div class="chart-card">
        <h3>热门 ATT&CK 战术</h3>
        <div class="tag-wrap">
          <span v-for="item in dashboard.top_tactics" :key="item.name" class="tag">
            {{ item.name }} / {{ item.count }}
          </span>
        </div>
      </div>
    </div>
  </section>
</template>
