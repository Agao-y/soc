<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import * as echarts from "echarts";
import type { Explainability } from "../api/client";

const props = defineProps<{
  explainability: Explainability | null;
  loading: boolean;
}>();

const container = ref<HTMLElement | null>(null);
let chart: echarts.ECharts | null = null;

const palette = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8", "#a78bfa"];

function buildOption(data: Explainability) {
  const rows = [...data.rows].sort((a, b) => b.contribution - a.contribution);
  const names = rows.map((r) => r.factor);
  const values = rows.map((r) => r.contribution);

  return {
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: any) => {
        const p = Array.isArray(params) ? params[0] : params;
        const idx = p.dataIndex;
        return `<b>${p.name}</b><br/>贡献值: <b style="color:#38bdf8">${values[idx]}</b> 分`;
      },
    },
    grid: { left: 10, right: 36, top: 12, bottom: 24 },
    xAxis: {
      type: "value",
      name: "分",
      nameTextStyle: { color: "#94a3b8", fontSize: 10 },
      axisLabel: { color: "#94a3b8", fontSize: 10 },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.08)" } },
      max: data.overall_score + 5,
    },
    yAxis: {
      type: "category",
      data: names,
      axisLabel: { color: "#cbd5e1", fontSize: 11 },
      axisLine: { show: false },
      axisTick: { show: false },
      inverse: true,
    },
    series: [
      {
        type: "bar",
        barWidth: "55%",
        data: values.map((v, i) => ({
          value: v,
          itemStyle: {
            color: palette[i],
            borderRadius: [0, 6, 6, 0],
          },
          label: {
            show: true,
            position: "right",
            color: "#edf6ff",
            fontSize: 12,
            fontWeight: "bold",
            formatter: `${v} 分`,
          },
        })),
      },
    ],
  } as echarts.EChartsOption;
}

function renderChart() {
  if (!container.value || !props.explainability) return;
  if (!chart) chart = echarts.init(container.value, undefined, { devicePixelRatio: 2 });
  chart.setOption(buildOption(props.explainability), true);
  chart.resize();
}

let resizeTimer: number | undefined;
function onResize() {
  if (resizeTimer) window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => chart?.resize(), 120);
}

watch(() => props.explainability, (val) => { if (val) renderChart(); });
onMounted(() => { window.addEventListener("resize", onResize); renderChart(); });
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
      <div ref="container" class="waterfall-chart"></div>
    </div>
    <div v-else class="empty-state">等待告警上下文载入。</div>
  </section>
</template>
