<script setup lang="ts">
import { computed } from "vue";
import type { DashboardData } from "../api/client";

const props = defineProps<{
  dashboard: DashboardData | null;
}>();

const total = computed(() =>
  (props.dashboard?.alert_type_distribution ?? []).reduce((sum, item) => sum + item.count, 0),
);
</script>

<template>
  <section class="panel panel-accent-violet distribution-panel">
    <div class="panel-heading">
      <h2>告警类型分布</h2>
      <span class="panel-tag">Pie + Bar View</span>
    </div>

    <div class="distribution-layout">
      <div class="pie-shell">
        <div class="pie-core">{{ total }}</div>
      </div>
      <div class="distribution-list">
        <article
          v-for="item in dashboard?.alert_type_distribution ?? []"
          :key="item.name"
          class="distribution-row"
        >
          <div class="sub-heading">
            <span>{{ item.name }}</span>
            <span>{{ item.count }}</span>
          </div>
          <div class="weight-bar">
            <div
              class="weight-fill"
              :style="{
                width: `${total ? (item.count / total) * 100 : 0}%`,
                background: item.color,
              }"
            ></div>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>
