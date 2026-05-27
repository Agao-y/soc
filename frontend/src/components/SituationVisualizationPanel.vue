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

  // 只取强度最高的前 15 条飞线，避免屏幕过于拥挤
  const topAttacks = [...attackMap]
    .sort((a, b) => b.intensity - a.intensity)
    .slice(0, 15);

  // 攻击源散点：按强度差异化大小，且限制显示数量
  const scatterData = topAttacks.map((point) => ({
    name: point.name,
    value: [point.longitude, point.latitude, point.attacks],
    intensity: point.intensity,
  }));

  // 飞线数据
  const lineData = topAttacks.map((point) => ({
    coords: [[point.longitude, point.latitude], defendPoint.value],
    value: point.attacks,
  }));

  // 攻击源光环 (大圈脉冲)
  const haloData = topAttacks.map((point) => ({
    name: "",
    value: [point.longitude, point.latitude, 1],
  }));

  return {
    backgroundColor: "transparent",
    globe: {
      baseTexture: createEarthTexture(),
      shading: "color",
      globeRadius: 96,
      globeOuterRadius: 97,
      viewControl: {
        autoRotate: true,
        autoRotateSpeed: 1.2,
        autoRotateAfterStill: 3,
        damping: 0.08,
        distance: 185,
        minDistance: 120,
        maxDistance: 320,
        targetCoord: [108, 26],
        alpha: 30,
        beta: 150,
      },
      light: {
        main: { intensity: 1.6, shadow: true },
        ambient: { intensity: 0.7 },
      },
      // 关掉大气辉光消除透明感，解决背面色点穿透
      atmosphere: { enable: false },
      // 开启深度纹理辅助遮挡
      postEffect: { enable: false },
    },
    series: [
      // 一、攻击源光晕 (静默大圆点)
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: 28,
        itemStyle: { color: "rgba(248, 113, 113, 0.28)" },
        silent: true,
        z: 1,
        data: haloData,
      },
      // 二、攻击源实心点
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: (val: number[]) => {
          const intensity = (val as any).intensity ?? 0.5;
          return 8 + intensity * 14;
        },
        itemStyle: {
          color: "#fb923c",
          borderColor: "#fed7aa",
          borderWidth: 1.5,
          shadowBlur: 6,
          shadowColor: "rgba(249, 115, 22, 0.6)",
        },
        label: {
          show: true,
          formatter: "{b}",
          color: "#fde68a",
          fontSize: 10,
          distance: 8,
          textBorderColor: "rgba(0,0,0,0.6)",
          textBorderWidth: 2,
        },
        emphasis: {
          itemStyle: { color: "#fbbf24", borderWidth: 2.5 },
          label: { fontSize: 13 },
        },
        z: 2,
        data: scatterData,
      },
      // 三、SOC 防御中心光环
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: 50,
        itemStyle: { color: "rgba(56, 189, 248, 0.18)" },
        silent: true,
        z: 1,
        data: [{ name: "", value: [...defendPoint.value, 1] }],
      },
      // 四、SOC 防御中心 (蓝色核心)
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        symbolSize: 20,
        itemStyle: {
          color: "#38bdf8",
          borderColor: "#bae6fd",
          borderWidth: 2.5,
          shadowBlur: 10,
          shadowColor: "rgba(56, 189, 248, 0.7)",
        },
        label: {
          show: true,
          formatter: defendPoint.name,
          color: "#bae6fd",
          fontSize: 13,
          fontWeight: "bold",
          distance: 12,
          textBorderColor: "rgba(0,0,0,0.65)",
          textBorderWidth: 3,
        },
        emphasis: { scale: 1.3 },
        z: 3,
        data: [{ name: defendPoint.name, value: [...defendPoint.value, 1] }],
      },
      // 五、攻击飞线 (加强清晰度)
      {
        type: "lines3D",
        coordinateSystem: "globe",
        polyline: false,
        effect: {
          show: true,
          period: 3.5,
          trailWidth: 7,
          trailLength: 0.32,
          trailOpacity: 1,
          trailColor: "#f87171",
          symbol: "arrow",
          symbolSize: 7,
        },
        lineStyle: {
          width: 3.5,
          color: "rgba(252, 165, 165, 0.9)",
          curveness: 0.3,
          opacity: 1,
        },
        z: 4,
        data: lineData,
      },
    ],
  };
}

function buildDistributionOption(): echarts.EChartsOption {
  const distribution = props.dashboard?.alert_type_distribution ?? [];
  const total = distribution.reduce((sum, d) => sum + d.count, 0);

  // 按数量降序排列，饼图和柱状图共用
  const sorted = [...distribution].sort((a, b) => b.count - a.count);

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
    legend: {
      bottom: 0,
      textStyle: { color: "#9bb2ca", fontSize: 11 },
      selectedMode: "multiple",
    },
    grid: { left: "54%", right: 10, top: 24, bottom: 48, containLabel: true },
    xAxis: {
      type: "value",
      axisLabel: { color: "#7f9ab5" },
      splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.08)" } },
    },
    yAxis: {
      type: "category",
      data: sorted.map((item) => item.name),
      axisLabel: { color: "#cfe4ff" },
      axisLine: { show: false },
      axisTick: { show: false },
      inverse: true,
    },
    series: [
      {
        type: "pie",
        radius: ["34%", "58%"],
        center: ["24%", "42%"],
        animationType: "scale",
        animationEasing: "elasticOut" as any,
        label: {
          color: "#d9ebff",
          formatter: "{b}\n{d}%",
          fontSize: 10,
        },
        labelLine: { lineStyle: { color: "rgba(148, 163, 184, 0.35)" } },
        emphasis: {
          scaleSize: 12,
          label: { fontSize: 14 },
          focus: "self",
          blurScope: "coordinateSystem",
        },
        blur: {
          itemStyle: { opacity: 0.3 },
          label: { opacity: 0.3 },
        },
        data: sorted.map((item) => ({
          value: item.count,
          name: item.name,
          itemStyle: {
            color: item.color,
            borderColor: "rgba(0,0,0,0.3)",
            borderWidth: 1,
          },
        })),
      },
      {
        type: "bar",
        xAxisIndex: 0,
        yAxisIndex: 0,
        barWidth: 14,
        animationDelay: (idx: number) => idx * 60,
        emphasis: {
          focus: "self",
          blurScope: "coordinateSystem",
          itemStyle: { opacity: 1, borderWidth: 1, borderColor: "#fff" },
        },
        blur: {
          itemStyle: { opacity: 0.3 },
        },
        data: sorted.map((item) => ({
          value: item.count,
          name: item.name,
          itemStyle: {
            color: item.color,
            borderRadius: [0, 8, 8, 0],
            opacity: 0.85,
          },
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
  linkCharts();
}

function renderDistribution() {
  if (!distributionRef.value) return;
  if (distributionChart) {
    distributionChart.dispose();
  }
  distributionChart = echarts.init(distributionRef.value);
  distributionChart.setOption(buildDistributionOption());
  linkCharts();
}

function linkCharts() {
  if (globeChart && distributionChart) {
    globeChart.group = "soc-dashboard";
    distributionChart.group = "soc-dashboard";
    echarts.connect("soc-dashboard");
  }
}

function resizeCharts() {
  globeChart?.resize();
  distributionChart?.resize();
}

function onFullscreenChange() {
  // WebGL canvas 在全屏切入/切出时尺寸变化，上下文可能损坏，必须延迟重建
  setTimeout(() => {
    renderGlobe();
    distributionChart?.resize();
  }, 200);
}

watch(() => props.dashboard, () => {
  renderGlobe();
  renderDistribution();
}, { deep: true });

onMounted(() => {
  renderGlobe();
  renderDistribution();
  window.addEventListener("resize", resizeCharts);
  document.addEventListener("fullscreenchange", onFullscreenChange);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", resizeCharts);
  document.removeEventListener("fullscreenchange", onFullscreenChange);
  if (globeChart && distributionChart) {
    echarts.disconnect("soc-dashboard");
  }
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
