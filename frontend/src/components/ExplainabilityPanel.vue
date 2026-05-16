<script setup lang="ts">
import type { Explainability } from "../api/client";

defineProps<{
  explainability: Explainability | null;
  loading: boolean;
}>();
</script>

<template>
  <section class="panel panel-accent-amber xai-panel">
    <div class="panel-heading">
      <h2>可解释性面板（XAI）</h2>
      <span class="panel-tag">Explainable AI</span>
    </div>

    <div v-if="loading && !explainability" class="empty-state">正在计算关键特征权重...</div>
    <div v-else-if="explainability" class="stack-list">
      <article v-for="row in explainability.rows" :key="row.factor" class="xai-card">
        <div class="sub-heading">
          <span>{{ row.factor }}</span>
          <span>{{ Math.round(row.weight * 100) }}%</span>
        </div>
        <div class="weight-bar">
          <div class="weight-fill" :style="{ width: `${row.weight * 100}%` }"></div>
        </div>
        <p>{{ row.note }}</p>
      </article>
    </div>
    <div v-else class="empty-state">等待告警上下文载入。</div>
  </section>
</template>
