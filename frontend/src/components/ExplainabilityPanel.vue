<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";
import * as echarts from "echarts";
import type { Explainability } from "../api/client";

const props = defineProps<{
  explainability: Explainability | null;
  loading: boolean;
}>();

const container = ref<HTMLElement | null>(null);
let chart: echarts.ECharts | null = null;

function render() {
  if (!container.value || !props.explainability) return;
  const data = props.explainability;
  const rows = [...data.rows].sort((a, b) => b.contribution - a.contribution);

  if (!chart) {
    chart = echarts.init(container.value);
  }

  chart.setOption({
    backgroundColor: "transparent",
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      backgroundColor: "rgba(8,19,38,0.95)",
      borderColor: "rgba(96,165,250,0.2)",
      textStyle: { color: "#edf6ff", fontSize: 12 },
      formatter: (ps: any) => {
        const i = ps[0].dataIndex;
        return `<b>${rows[i].factor}</b><br/>贡献: <b style="color:#38bdf8">${rows[i].contribution}</b> 分`;
      },
    },
    grid: { left: 4, right: 50, top: 8, bottom: 4, containLabel: true },
    xAxis: {
      type: "value",
      name: "分",
      nameTextStyle: { color: "#94a3b8", fontSize: 10 },
      axisLabel: { color: "#94a3b8", fontSize: 10 },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.1)" } },
    },
    yAxis: {
      type: "category",
      data: rows.map((r) => r.factor),
      axisLabel: { color: "#cbd5e1", fontSize: 11 },
      axisLine: { show: false },
      axisTick: { show: false },
      inverse: true,
    },
    series: [{
      type: "bar",
      barWidth: 16,
      barGap: "30%",
      data: rows.map((r, i) => {
        const colors = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8", "#a78bfa"];
        return {
          value: r.contribution,
          itemStyle: {
            color: colors[i],
            borderRadius: [0, 4, 4, 0],
          },
          label: {
            show: true,
            position: "right",
            distance: 6,
            color: "#edf6ff",
            fontSize: 12,
            fontWeight: "bold",
            formatter: `${r.contribution}`,
          },
        };
      }),
    }],
  } as echarts.EChartsOption, true);

  chart.resize();
}

async function safeRender() {
  await nextTick();
  render();
}

watch(() => props.explainability, safeRender);
onMounted(safeRender);

function onResize() { chart?.resize(); }
onMounted(() => window.addEventListener("resize", onResize));
onBeforeUnmount(() => {
  window.removeEventListener("resize", onResize);
  chart?.dispose();
  chart = null;
});
</script>

<template>
  <section class="panel panel-accent-amber xai-panel">
    <div class="panel-heading">
      <h2>可解释性面板（XAI）</h2>
      <span class="panel-tag">Explainable AI</span>
    </div>

    <div v-if="loading && !explainability" class="empty-state">正在计算特征贡献...</div>
    <div v-else-if="explainability" class="xai-layout">
      <div class="xai-score-badge">
        <span>综合评分</span>
        <strong>{{ explainability.overall_score }}</strong>
        <small>/ 100</small>
      </div>
      <div ref="container" class="xai-chart-box"></div>
    </div>
    <div v-else class="empty-state">等待告警上下文载入。</div>
  </section>
</template>
