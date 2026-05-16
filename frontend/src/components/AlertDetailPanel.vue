<script setup lang="ts">
import type { AlertDetail } from "../api/client";

defineProps<{
  detail: AlertDetail | null;
  loading: boolean;
}>();
</script>

<template>
  <section class="panel detail-panel">
    <div class="section-title-row">
      <h2>智能研判结果</h2>
      <span v-if="detail" class="pill">{{ detail.assessment.label }}</span>
    </div>

    <div v-if="loading && !detail" class="empty-state">正在生成智能研判...</div>
    <div v-else-if="detail" class="detail-stack">
      <div class="score-band">
        <div>
          <span class="muted">综合风险分</span>
          <strong>{{ detail.assessment.overall_score }}</strong>
        </div>
        <div>
          <span class="muted">异常分</span>
          <strong>{{ detail.assessment.anomaly_score }}</strong>
        </div>
        <div>
          <span class="muted">误报概率</span>
          <strong>{{ Math.round(detail.assessment.false_positive_probability * 100) }}%</strong>
        </div>
      </div>

      <article class="content-card">
        <h3>LLM 研判结论</h3>
        <p>{{ detail.assessment.reasoning }}</p>
      </article>

      <article class="content-card">
        <h3>处置建议</h3>
        <ul class="bullet-list">
          <li v-for="item in detail.assessment.recommendations" :key="item">{{ item }}</li>
        </ul>
      </article>

      <article class="content-card">
        <h3>溯源时间线</h3>
        <ul class="timeline-list">
          <li v-for="item in detail.assessment.trace_summary" :key="item">{{ item }}</li>
        </ul>
      </article>
    </div>
    <div v-else class="empty-state">请选择左侧告警查看详情。</div>
  </section>
</template>
