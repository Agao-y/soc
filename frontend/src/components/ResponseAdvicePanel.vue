<script setup lang="ts">
import type { AlertDetail } from "../api/client";

defineProps<{
  detail: AlertDetail | null;
  loading: boolean;
}>();
</script>

<template>
  <section class="panel panel-accent-emerald advice-panel">
    <div class="panel-heading">
      <h2>处置建议</h2>
      <span class="panel-tag">Response</span>
    </div>

    <div v-if="loading && !detail" class="empty-state">正在生成处置建议...</div>
    <div v-else-if="detail" class="stack-list">
      <!-- LLM 预测防御建议 -->
      <article v-if="detail.prediction?.recommended_defense.length" class="info-card">
        <h3>AI 推演防御</h3>
        <ol class="ordered-list">
          <li v-for="item in detail.prediction.recommended_defense" :key="item">{{ item }}</li>
        </ol>
      </article>

      <!-- 处置步骤 -->
      <article class="info-card">
        <h3>处置步骤</h3>
        <ol class="ordered-list">
          <li v-for="item in detail.assessment.recommendations" :key="item">{{ item }}</li>
        </ol>
      </article>

      <!-- 同类事件 -->
      <article class="info-card compact-card">
        <h3>同类事件历史</h3>
        <div class="stats-inline">
          <span>累计 <strong>{{ detail.alert.similar_incidents.total }}</strong> 次</span>
          <span>近 7 天 <strong>{{ detail.alert.similar_incidents.last_7_days }}</strong> 次</span>
          <span>闭环率 <strong>{{ Math.round(detail.alert.similar_incidents.closed_rate * 100) }}%</strong></span>
        </div>
      </article>

      <!-- 加固建议（有内容才显示） -->
      <article v-if="detail.alert.hardening_suggestions.length" class="info-card compact-card">
        <h3>系统加固</h3>
        <ul class="plain-list">
          <li v-for="item in detail.alert.hardening_suggestions" :key="item">{{ item }}</li>
        </ul>
      </article>
    </div>
    <div v-else class="empty-state">等待 AI 输出建议。</div>
  </section>
</template>
