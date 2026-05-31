<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import * as echarts from "echarts";
import type { Explainability } from "../api/client";

const props = defineProps<{
  explainability: Explainability | null;
  loading: boolean;
}>();

const container = ref<HTMLElement | null>(null);
let chart: echarts.ECharts | null = null;

function buildWaterfallOption(data: Explainability) {
  const rows = data.rows;
  const features = rows.map((r) => r.factor);
  const contributions = rows.map((r) => r.contribution);

  // Build waterfall: transparent stack + visible fill
  const displayValues: number[] = [];
  const invisibleValues: number[] = [];
  let runningTotal = 0;

  contributions.forEach((val) => {
    invisibleValues.push(runningTotal);
    displayValues.push(val);
    runningTotal += val;
  });

  // Add "总分" bar
  features.push("综合评分");
  invisibleValues.push(0);
  displayValues.push(data.overall_score);

  const option: echarts.EChartsOption = {
    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      formatter: (params: any) => {
        const p = Array.isArray(params) ? params : [params];
        const show = p.find((x: any) => x.seriesName === "贡献值");
        if (!show || show.value === 0) return "";
        const idx = show.dataIndex;
        const last = idx === features.length - 1;
        return `<b>${show.name}</b><br/>${last ? "综合评分" : "贡献值"}: <b style="color:#38bdf8">${contributions[idx] ?? show.value}</b> 分`;
      },
    },
    grid: { left: 28, right: 40, top: 16, bottom: 28 },
    xAxis: {
      type: "category",
      data: features,
      axisLabel: { color: "#94a3b8", fontSize: 10, rotate: 20 },
      axisLine: { lineStyle: { color: "rgba(148,163,184,0.2)" } },
    },
    yAxis: {
      type: "value",
      name: "分",
      nameTextStyle: { color: "#94a3b8" },
      axisLabel: { color: "#94a3b8" },
      splitLine: { lineStyle: { color: "rgba(148,163,184,0.08)" } },
    },
    series: [
      {
        name: "基底",
        type: "bar",
        stack: "waterfall",
        data: invisibleValues,
        itemStyle: { color: "transparent" },
        emphasis: { itemStyle: { color: "transparent" } },
      },
      {
        name: "贡献值",
        type: "bar",
        stack: "waterfall",
        data: displayValues.map((v, i) => {
          const isTotal = i === displayValues.length - 1;
          const colors = ["#ef4444", "#f97316", "#facc15", "#22c55e", "#38bdf8", "#a78bfa"];
          return {
            value: v,
            itemStyle: {
              color: isTotal ? "#c084fc" : colors[i % colors.length],
              borderRadius: isTotal ? [0, 0, 4, 4] : [4, 4, 0, 0],
            },
            label: {
              show: true,
              position: "top",
              color: "#edf6ff",
              fontSize: 11,
              fontWeight: "bold",
              formatter: v > 0 ? `${v}` : "",
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
    chart = echarts.init(container.value);
  }
  chart.setOption(buildWaterfallOption(props.explainability), true);
  chart.resize();
}

let resizeTimer: number | undefined;
function onResize() {
  if (resizeTimer) window.clearTimeout(resizeTimer);
  resizeTimer = window.setTimeout(() => chart?.resize(), 100);
}

watch(() => props.explainability, (val) => { if (val) renderChart(); }, { deep: true });
onMounted(() => { window.addEventListener("resize", onResize); renderChart(); });
onBeforeUnmount(() => {
  window.removeEventListener("resize", onResize);
  chart?.dispose();
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
      <div ref="container" class="waterfall-chart"></div>
      <div class="xai-list">
        <article v-for="row in explainability.rows" :key="row.factor" class="xai-card">
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
