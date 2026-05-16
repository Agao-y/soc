<script setup lang="ts">
import type { Alert } from "../api/client";

defineProps<{
  alerts: Alert[];
  selectedAlertId: string;
  loading: boolean;
}>();

defineEmits<{
  select: [alertId: string];
}>();
</script>

<template>
  <section class="panel list-panel">
    <div class="section-title-row">
      <h2>告警队列</h2>
      <span class="pill">{{ alerts.length }} 条</span>
    </div>

    <div v-if="loading && !alerts.length" class="empty-state">正在加载告警数据...</div>

    <button
      v-for="alert in alerts"
      :key="alert.id"
      class="alert-card"
      :class="{ active: selectedAlertId === alert.id }"
      @click="$emit('select', alert.id)"
    >
      <div class="alert-card-top">
        <span class="severity" :data-level="alert.severity">{{ alert.severity }}</span>
        <span class="source">{{ alert.source }}</span>
      </div>
      <h3>{{ alert.title }}</h3>
      <p>{{ alert.description }}</p>
      <div class="alert-meta">
        <span>{{ alert.asset.hostname }}</span>
        <span>{{ alert.asset.environment }}</span>
      </div>
    </button>
  </section>
</template>
