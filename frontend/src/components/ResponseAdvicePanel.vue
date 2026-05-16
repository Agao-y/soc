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
      <h2>AI 生成处置建议</h2>
      <span class="panel-tag">Response Loop</span>
    </div>

    <div v-if="loading && !detail" class="empty-state">正在生成处置建议...</div>
    <div v-else-if="detail" class="stack-list">
      <article class="info-card">
        <h3>推荐处置步骤</h3>
        <ol class="ordered-list">
          <li v-for="item in detail.assessment.recommendations" :key="item">{{ item }}</li>
        </ol>
      </article>

      <article class="info-card">
        <h3>加固建议</h3>
        <ul v-if="detail.alert.hardening_suggestions.length" class="plain-list">
          <li v-for="item in detail.alert.hardening_suggestions" :key="item">{{ item }}</li>
        </ul>
        <p v-else>当前告警暂无额外加固建议，可结合资产基线继续补充。</p>
      </article>

      <article class="info-card compact-card">
        <h3>关联规则</h3>
        <div class="token-wrap">
          <span v-for="rule in detail.alert.related_rule_ids" :key="rule" class="token">{{ rule }}</span>
        </div>
      </article>

      <article class="info-card compact-card">
        <h3>同类事件历史统计</h3>
        <div class="stats-inline">
          <span>累计 {{ detail.alert.similar_incidents.total }}</span>
          <span>近 7 天 {{ detail.alert.similar_incidents.last_7_days }}</span>
          <span>闭环率 {{ Math.round(detail.alert.similar_incidents.closed_rate * 100) }}%</span>
        </div>
      </article>
    </div>
    <div v-else class="empty-state">等待 AI 输出建议。</div>
  </section>
</template>
