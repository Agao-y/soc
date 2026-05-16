<script setup lang="ts">
import type { DashboardData } from "../api/client";

defineProps<{
  dashboard: DashboardData | null;
}>();

const labels: Record<string, string> = {
  pending: "待处理",
  processing: "处理中",
  closed: "已闭环",
  ignored: "误报已忽略",
};
</script>

<template>
  <section class="panel panel-accent-slate ticket-panel">
    <div class="panel-heading">
      <h2>处置工单流转面板</h2>
      <span class="panel-tag">Ticket Flow</span>
    </div>

    <div v-if="dashboard" class="stack-list">
      <div class="ticket-summary-grid">
        <article class="mini-stat">
          <span>待处理</span>
          <strong>{{ dashboard.ticket_flow.pending }}</strong>
        </article>
        <article class="mini-stat">
          <span>处理中</span>
          <strong>{{ dashboard.ticket_flow.processing }}</strong>
        </article>
        <article class="mini-stat">
          <span>已闭环</span>
          <strong>{{ dashboard.ticket_flow.closed }}</strong>
        </article>
        <article class="mini-stat">
          <span>误报已忽略</span>
          <strong>{{ dashboard.ticket_flow.ignored }}</strong>
        </article>
      </div>

      <article class="info-card compact-card">
        <h3>平均响应速度</h3>
        <div class="stats-inline">
          <span>{{ dashboard.ticket_flow.avg_response_minutes }} min</span>
        </div>
      </article>

      <article
        v-for="(record, index) in dashboard.ticket_flow.recent_records"
        :key="`${record.assignee}-${index}`"
        class="ticket-record"
      >
        <div class="sub-heading">
          <span>{{ labels[record.status] }}</span>
          <span>{{ record.assignee }}</span>
        </div>
        <div class="stats-inline">
          <span>{{ new Date(record.updated_at).toLocaleString("zh-CN", { hour12: false }) }}</span>
          <span>{{ record.response_minutes }} 分钟</span>
        </div>
      </article>
    </div>
  </section>
</template>
