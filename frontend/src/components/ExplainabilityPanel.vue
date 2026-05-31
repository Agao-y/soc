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

function buildWaterfallOption(data: Explainability) {
  const rows = [...data.rows].sort((a, b) => b.contribution - a.contribution);
  const features = rows.map((r) => r.factor);
  const contributions = rows.map((r) => r.contribution);

  const base: number[] = [];
  const vals: number[] = [];
  let acc = 0;
  contributions.forEach((c) => { base.push(acc); vals.push(c); acc += c; });

  const option: echarts.EChartsOption = {
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: any) => {
        const p = Array.isArray(params) ? params : [params];
        const vis = p.find((x: any) => x.seriesName === "贡献值");
        if (!vis || vis.value === 0) return "";
        const idx = vis.dataIndex;
        return `<b>${vis.name}</b><br/>贡献: <b style="color:#38bdf8">${contributions[idx]}</b> 分<br/>占比: <b style="color:#c084fc">${data.overall_score > 0 ? Math.round(contributions[idx] / data.overall_score * 100) : 0}%</b>`;
      },
    },
    grid: { left: 30, right: 48, top: 20, bottom: 32 },
    xAxis: {
      type: "category",
      data: features,
      axisLabel: { color: "#94a3b8", fontSize: 10, rotate: 18, interval: 0 },
      axisLine: { lineStyle: { color: "rgba(148,163,184,0.2)" } },
      axisTick: { show: false },
    },
    yAxis: {
      type: "value",
      name: "分",
      nameTextStyle: { color: "#94a3b8", fontSize: 11 },
      axisLabel: { color: "#94a3b8", fontSize: 10 },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.08)" } },
    },
    series: [
      {
        name: "基底",
        type: "bar",
        stack: "wf",
        data: base,
        itemStyle: { color: "transparent", borderColor: "transparent" },
        emphasis: { itemStyle: { color: "transparent" } },
        barWidth: "55%",
      },
      {
        name: "贡献值",
        type: "bar",
        stack: "wf",
        barWidth: "55%",
        data: vals.map((v, i) => {
          const palette = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8", "#a78bfa"];
          return {
            value: v,
            itemStyle: {
              color: palette[i % palette.length],
              borderRadius: [4, 4, 0, 0],
            },
            label: {
              show: v > 0,
              position: "insideTop",
              color: "#fff",
              fontSize: 10,
              fontWeight: "bold",
              formatter: `+${v}`,
              offset: [0, -4],
            },
          };
        }),
      },
    ],
  };
  return option;
}

function renderChart() {
  if (!container.value || !props.explainability) return;
  if (!chart) {
    chart = echarts.init(container.value, undefined, { devicePixelRatio: 2 });
  }
  chart.setOption(buildWaterfallOption(props.explainability), true);
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
      <div class="xai-list">
        <article v-for="row in [...explainability.rows].sort((a,b) => b.contribution - a.contribution)" :key="row.factor" class="xai-card">
          <div class="xai-bar-row">
            <span class="xai-factor">{{ row.factor }}</span>
            <span class="xai-contrib">{{ row.contribution }} 分</span>
            <span class="xai-pct">{{ Math.round(row.weight * 100) }}%</span>
          </div>
          <div class="weight-bar">
            <div class="weight-fill" :style="{ width: `${row.weight * 100}%` }"></div>
          </div>
          <p class="xai-note">{{ row.note }}</p>
        </article>
      </div>
    </div>
    <div v-else class="empty-state">等待告警上下文载入。</div>
  </section>
</template>
