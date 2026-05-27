<script setup lang="ts">
import { geoEquirectangular, geoPath } from "d3-geo";
import * as echarts from "echarts";
import "echarts-gl";
import { feature, mesh } from "topojson-client";
import worldAtlas from "world-atlas/countries-110m.json";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { DashboardData } from "../api/client";

const props = defineProps<{
  dashboard: DashboardData | null;
}>();

const globeRef = ref<HTMLDivElement | null>(null);
const distributionRef = ref<HTMLDivElement | null>(null);
let globeChart: echarts.ECharts | null = null;
let distributionChart: echarts.ECharts | null = null;

const defendPoint = { name: "龙王 SOC 中心", value: [121.4737, 31.2304] };

function createEarthTexture() {
  const canvas = document.createElement("canvas");
  canvas.width = 2048;
  canvas.height = 1024;
  const ctx = canvas.getContext("2d");
  if (!ctx) return canvas;

  const ocean = ctx.createLinearGradient(0, 0, 0, canvas.height);
  ocean.addColorStop(0, "#020f1f");
  ocean.addColorStop(0.45, "#0b2e4f");
  ocean.addColorStop(1, "#04101d");
  ctx.fillStyle = ocean;
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  for (let i = 0; i < 160; i += 1) {
    ctx.fillStyle = `rgba(125, 211, 252, ${0.015 + (i % 7) * 0.01})`;
    ctx.beginPath();
    ctx.arc((i * 83 + i * 7) % canvas.width, (i * 41 + i * 13) % canvas.height, 0.5 + (i % 4) * 0.8, 0, Math.PI * 2);
    ctx.fill();
  }

  const projection = geoEquirectangular().fitSize([canvas.width, canvas.height], { type: "Sphere" });
  const path = geoPath(projection, ctx);
  const countries = feature(worldAtlas as any, (worldAtlas as any).objects.countries) as any;
  const borders = mesh(worldAtlas as any, (worldAtlas as any).objects.countries, (a: any, b: any) => a !== b) as any;

  const land = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
  land.addColorStop(0, "rgba(71, 196, 255, 0.42)");
  land.addColorStop(0.55, "rgba(37, 136, 226, 0.46)");
  land.addColorStop(1, "rgba(23, 86, 154, 0.38)");
  ctx.fillStyle = land;
  ctx.beginPath();
  path(countries);
  ctx.fill();

  ctx.strokeStyle = "rgba(219, 234, 254, 0.18)";
  ctx.lineWidth = 1;
  ctx.beginPath();
  path(borders);
  ctx.stroke();

  ctx.shadowColor = "rgba(96, 165, 250, 0.5)";
  ctx.shadowBlur = 14;
  ctx.strokeStyle = "rgba(125, 211, 252, 0.42)";
  ctx.lineWidth = 1.7;
  ctx.beginPath();
  path(borders);
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Grid lines
  ctx.strokeStyle = "rgba(56, 189, 248, 0.08)";
  ctx.lineWidth = 0.8;
  for (let x = 0; x < canvas.width; x += 96) {
    ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, canvas.height); ctx.stroke();
  }
  for (let y = 0; y < canvas.height; y += 96) {
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(canvas.width, y); ctx.stroke();
  }

  // Equator highlight
  ctx.strokeStyle = "rgba(56, 189, 248, 0.28)";
  ctx.lineWidth = 3;
  ctx.beginPath();
  ctx.moveTo(0, canvas.height / 2);
  ctx.lineTo(canvas.width, canvas.height / 2);
  ctx.stroke();

  ctx.strokeStyle = "rgba(125, 211, 252, 0.24)";
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  path({ type: "Sphere" } as any);
  ctx.stroke();

  return canvas;
}

function buildGlobeOption(): any {
  const attackMap = props.dashboard?.attack_map ?? [];

  const scatterData = attackMap.map((point) => ({
    name: point.name,
    value: [point.longitude, point.latitude, point.attacks],
  }));

  const lineData = attackMap.map((point) => ({
    coords: [[point.longitude, point.latitude], defendPoint.value],
    value: point.attacks,
  }));

  return {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(5, 17, 34, 0.95)",
      borderColor: "rgba(56, 189, 248, 0.35)",
      textStyle: { color: "#e6f4ff", fontSize: 12 },
      formatter: (params: any) => {
        if (params.seriesType === "lines3D") return `攻击飞线 → ${defendPoint.name}`;
        const v = params?.value ?? [];
        return `${params?.name ?? "未知源头"}<br/>经度 ${Number(v[0]).toFixed(2)} / 纬度 ${Number(v[1]).toFixed(2)}<br/>攻击强度 ${v[2] ?? 0}`;
      },
    },
    globe: {
      baseTexture: createEarthTexture(),
      shading: "lambert",
      environment: "#020617",
      globeRadius: 95,
      viewControl: {
        autoRotate: true,
        autoRotateSpeed: 1.5,
        autoRotateAfterStill: 3,
        damping: 0.1,
        distance: 175,
        minDistance: 110,
        maxDistance: 300,
        targetCoord: [108, 26],
        alpha: 25,
        beta: 155,
      },
      light: {
        main: { intensity: 1.3, shadow: false },
        ambient: { intensity: 0.6 },
      },
      atmosphere: { enable: true, glowPower: 4.5, innerGlowPower: 1.2 },
    },
    series: [
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: (value: number[]) => 8 + Number(value[2]) * 2.2,
        itemStyle: { color: "#f97316", borderColor: "#fff7ed", borderWidth: 1 },
        label: { show: true, formatter: "{b}", color: "#d9ebff", fontSize: 9, distance: 6 },
        emphasis: { itemStyle: { color: "#fb923c", borderWidth: 2 }, label: { fontSize: 12 } },
        data: scatterData,
      },
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: 40,
        itemStyle: { color: "rgba(56, 189, 248, 0.22)" },
        silent: true,
        data: [{ name: "", value: [...defendPoint.value, 1] }],
      },
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: 18,
        itemStyle: { color: "#67e8f9", borderColor: "#e0f2fe", borderWidth: 2 },
        label: { show: true, formatter: defendPoint.name, color: "#d5f5ff", fontSize: 12, fontWeight: "bold", distance: 10 },
        data: [{ name: defendPoint.name, value: [...defendPoint.value, 1] }],
      },
      {
        type: "lines3D",
        coordinateSystem: "globe",
        effect: {
          show: true,
          period: 4,
          trailWidth: 5,
          trailLength: 0.28,
          trailOpacity: 0.95,
          trailColor: "#ef4444",
          symbol: "arrow",
          symbolSize: 5,
        },
        lineStyle: { width: 2, color: "rgba(248, 113, 113, 0.8)", curveness: 0.25 },
        data: lineData,
      },
    ],
  };
}

function buildDistributionOption(): echarts.EChartsOption {
  const distribution = props.dashboard?.alert_type_distribution ?? [];
  const total = distribution.reduce((sum, d) => sum + d.count, 0);

  return {
    animationDuration: 800,
    animationEasing: "cubicOut" as any,
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(5, 17, 34, 0.95)",
      borderColor: "rgba(56, 189, 248, 0.35)",
      textStyle: { color: "#e6f4ff" },
      formatter: (params: any) => {
        const pct = total > 0 ? ((params.value / total) * 100).toFixed(1) : "0";
        return `${params.name}<br/>数量: ${params.value}<br/>占比: ${pct}%`;
      },
    },
    legend: { bottom: 0, textStyle: { color: "#9bb2ca", fontSize: 11 } },
    grid: { left: "54%", right: 10, top: 24, bottom: 48, containLabel: true },
    xAxis: { type: "value", axisLabel: { color: "#7f9ab5" }, splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.08)" } } },
    yAxis: { type: "category", data: distribution.map((item) => item.name), axisLabel: { color: "#cfe4ff" }, axisLine: { show: false }, axisTick: { show: false } },
    series: [
      {
        type: "pie",
        radius: ["34%", "58%"],
        center: ["24%", "42%"],
        animationType: "scale",
        animationEasing: "elasticOut" as any,
        label: { color: "#d9ebff", formatter: "{b}\n{d}%", fontSize: 10 },
        labelLine: { lineStyle: { color: "rgba(148, 163, 184, 0.35)" } },
        emphasis: { scaleSize: 12, label: { fontSize: 14 } },
        data: distribution.map((item) => ({
          value: item.count, name: item.name,
          itemStyle: { color: item.color, borderColor: "rgba(0,0,0,0.3)", borderWidth: 1 },
        })),
      },
      {
        type: "bar",
        xAxisIndex: 0, yAxisIndex: 0, barWidth: 14,
        animationDelay: (idx: number) => idx * 60,
        data: distribution.map((item) => ({
          value: item.count,
          itemStyle: { color: item.color, borderRadius: [0, 8, 8, 0], opacity: 0.85 },
          emphasis: { itemStyle: { opacity: 1, borderWidth: 1, borderColor: "#fff" } },
        })),
      },
    ],
  };
}

function renderGlobe() {
  if (!globeRef.value) return;
  if (globeChart) {
    globeChart.dispose();
  }
  globeChart = echarts.init(globeRef.value);
  globeChart.setOption(buildGlobeOption());
}

function renderDistribution() {
  if (!distributionRef.value) return;
  if (distributionChart) {
    distributionChart.dispose();
  }
  distributionChart = echarts.init(distributionRef.value);
  distributionChart.setOption(buildDistributionOption());
}

function resizeCharts() {
  globeChart?.resize();
  distributionChart?.resize();
}

watch(() => props.dashboard, () => {
  renderGlobe();
  renderDistribution();
}, { deep: true });

onMounted(() => {
  renderGlobe();
  renderDistribution();
  window.addEventListener("resize", resizeCharts);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", resizeCharts);
  globeChart?.dispose();
  distributionChart?.dispose();
});
</script>

<template>
  <section class="panel panel-accent-danger visualization-panel">
    <div class="panel-heading">
      <h2>态势可视化引擎</h2>
      <span class="panel-tag">3D 地球 + 实时攻击态势</span>
    </div>

    <div class="visualization-grid">
      <article class="viz-card">
        <div class="sub-heading">
          <span>全球攻击态势</span>
          <span>实时飞线追踪</span>
        </div>
        <div ref="globeRef" class="chart-canvas globe-canvas"></div>
      </article>

      <article class="viz-card">
        <div class="sub-heading">
          <span>告警类型分布</span>
          <span>饼图 + 柱状图联动分析</span>
        </div>
        <div ref="distributionRef" class="chart-canvas distribution-canvas"></div>
      </article>
    </div>
  </section>
</template>
