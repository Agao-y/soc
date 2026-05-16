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
let pulseTimer: number | undefined;
let pulsePhase = 0;

const defendPoint = { name: "Dragon SOC", value: [121.4737, 31.2304] };
const globeView = {
  alpha: 20,
  beta: 155,
  distance: 175,
};

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

  for (let i = 0; i < 110; i += 1) {
    ctx.fillStyle = `rgba(125, 211, 252, ${0.018 + (i % 5) * 0.008})`;
    ctx.beginPath();
    ctx.arc((i * 83) % canvas.width, (i * 41) % canvas.height, 1 + (i % 3), 0, Math.PI * 2);
    ctx.fill();
  }

  const projection = geoEquirectangular().fitSize([canvas.width, canvas.height], { type: "Sphere" });
  const path = geoPath(projection, ctx);
  const countries = feature(worldAtlas as any, (worldAtlas as any).objects.countries) as any;
  const borders = mesh(
    worldAtlas as any,
    (worldAtlas as any).objects.countries,
    (a: any, b: any) => a !== b,
  ) as any;

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

  ctx.strokeStyle = "rgba(56, 189, 248, 0.12)";
  ctx.lineWidth = 1;
  for (let x = 0; x < canvas.width; x += 128) {
    ctx.beginPath();
    ctx.moveTo(x, 0);
    ctx.lineTo(x, canvas.height);
    ctx.stroke();
  }
  for (let y = 0; y < canvas.height; y += 128) {
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(canvas.width, y);
    ctx.stroke();
  }

  ctx.strokeStyle = "rgba(125, 211, 252, 0.24)";
  ctx.lineWidth = 2.2;
  ctx.beginPath();
  path({ type: "Sphere" } as any);
  ctx.stroke();

  return canvas;
}

function buildGlobeOption(): any {
  const attackMap = props.dashboard?.attack_map ?? [];
  const attackPulse = pulsePhase % 2 === 0 ? 1.04 : 1.18;
  const defendPulse = pulsePhase % 2 === 0 ? 1.14 : 1.42;
  const scatterData = attackMap.map((point) => ({
    name: point.name,
    value: [point.longitude, point.latitude, point.attacks],
  }));
  const lineData = attackMap.map((point) => ({
    coords: [
      [point.longitude, point.latitude],
      defendPoint.value,
    ],
    value: point.attacks,
  }));

  return {
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(5, 17, 34, 0.92)",
      borderColor: "rgba(56, 189, 248, 0.22)",
      textStyle: { color: "#e6f4ff" },
      formatter: (params: any) => {
        if (params.seriesType === "lines3D") {
          return `攻击飞线<br/>目标：${defendPoint.name}`;
        }
        const value = params?.value ?? [];
        return `${params?.name ?? "未知"}<br/>经度 ${value[0]} / 纬度 ${value[1]}<br/>攻击强度 ${value[2] ?? 0}`;
      },
    },
    globe: {
      baseTexture: createEarthTexture(),
      shading: "lambert",
      environment: "#020617",
      globeRadius: 95,
      viewControl: {
        autoRotate: true,
        autoRotateSpeed: -1.6,
        autoRotateAfterStill: 0,
        damping: 0.15,
        distance: globeView.distance,
        minDistance: 120,
        maxDistance: 300,
        targetCoord: [108, 26],
        alpha: globeView.alpha,
        beta: globeView.beta,
      },
      light: {
        main: {
          intensity: 1.25,
          shadow: false,
        },
        ambient: {
          intensity: 0.55,
        },
      },
      postEffect: {
        enable: true,
      },
    },
    series: [
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        blendMode: "lighter",
        symbolSize: (value: number[]) => (10 + Number(value[2]) * 1.8) * attackPulse,
        itemStyle: {
          color: "#f97316",
          opacity: 0.98,
          borderColor: "#fff7ed",
          borderWidth: 0.8,
        },
        label: {
          show: true,
          formatter: "{b}",
          color: "#d9ebff",
          fontSize: 10,
        },
        data: scatterData,
      },
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        blendMode: "lighter",
        symbolSize: 30 * defendPulse,
        itemStyle: {
          color: "rgba(56, 189, 248, 0.26)",
          opacity: 0.9,
        },
        silent: true,
        data: [{ name: defendPoint.name, value: [...defendPoint.value, 1] }],
      },
      {
        type: "scatter3D",
        coordinateSystem: "globe",
        blendMode: "lighter",
        symbolSize: 16 * defendPulse,
        itemStyle: {
          color: "#67e8f9",
          opacity: 1,
          borderColor: "#e0f2fe",
          borderWidth: 1.6,
        },
        label: {
          show: true,
          formatter: defendPoint.name,
          color: "#d5f5ff",
          fontSize: 11,
          distance: 8,
        },
        data: [{ name: defendPoint.name, value: [...defendPoint.value, 1] }],
      },
      {
        type: "lines3D",
        coordinateSystem: "globe",
        blendMode: "lighter",
        effect: {
          show: true,
          trailWidth: 4.5,
          trailLength: 0.24,
          trailOpacity: 0.92,
          trailColor: "#ef4444",
        },
        lineStyle: {
          width: 1.8,
          color: "rgba(248, 113, 113, 0.72)",
          opacity: 0.46,
        },
        data: lineData,
      },
    ],
  };
}

function buildDistributionOption(): echarts.EChartsOption {
  const distribution = props.dashboard?.alert_type_distribution ?? [];
  return {
    animationDuration: 700,
    backgroundColor: "transparent",
    tooltip: {
      trigger: "item",
      backgroundColor: "rgba(5, 17, 34, 0.92)",
      borderColor: "rgba(56, 189, 248, 0.22)",
      textStyle: { color: "#e6f4ff" },
    },
    legend: {
      bottom: 0,
      textStyle: { color: "#9bb2ca" },
    },
    grid: {
      left: "54%",
      right: 10,
      top: 24,
      bottom: 48,
      containLabel: true,
    },
    xAxis: {
      type: "value",
      axisLabel: { color: "#7f9ab5" },
      splitLine: { lineStyle: { color: "rgba(148, 163, 184, 0.08)" } },
    },
    yAxis: {
      type: "category",
      data: distribution.map((item) => item.name),
      axisLabel: { color: "#cfe4ff" },
      axisLine: { show: false },
      axisTick: { show: false },
    },
    series: [
      {
        type: "pie",
        radius: ["34%", "56%"],
        center: ["24%", "42%"],
        label: { color: "#d9ebff" },
        labelLine: { lineStyle: { color: "rgba(148, 163, 184, 0.35)" } },
        data: distribution.map((item) => ({
          value: item.count,
          name: item.name,
          itemStyle: { color: item.color },
        })),
      },
      {
        type: "bar",
        xAxisIndex: 0,
        yAxisIndex: 0,
        barWidth: 14,
        data: distribution.map((item) => ({
          value: item.count,
          itemStyle: {
            color: item.color,
            borderRadius: [0, 8, 8, 0],
          },
        })),
      },
    ],
  };
}

function renderCharts() {
  if (globeRef.value) {
    globeChart ??= echarts.init(globeRef.value);
    globeChart.setOption(buildGlobeOption());
  }
  if (distributionRef.value) {
    distributionChart ??= echarts.init(distributionRef.value);
    distributionChart.setOption(buildDistributionOption());
  }
}

function resizeCharts() {
  globeChart?.resize();
  distributionChart?.resize();
}

watch(() => props.dashboard, renderCharts, { deep: true });

onMounted(() => {
  renderCharts();
  window.addEventListener("resize", resizeCharts);
  pulseTimer = window.setInterval(() => {
    pulsePhase += 1;
    renderCharts();
  }, 1200);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", resizeCharts);
  if (pulseTimer) {
    window.clearInterval(pulseTimer);
  }
  globeChart?.dispose();
  distributionChart?.dispose();
});
</script>

<template>
  <section class="panel panel-accent-danger visualization-panel">
    <div class="panel-heading">
      <h2>态势可视化引擎</h2>
      <span class="panel-tag">3D Globe + ECharts</span>
    </div>

    <div class="visualization-grid">
      <article class="viz-card">
        <div class="sub-heading">
          <span>攻击态势热力图</span>
          <span>3D Globe Attack Lines</span>
        </div>
        <div ref="globeRef" class="chart-canvas globe-canvas"></div>
      </article>

      <article class="viz-card">
        <div class="sub-heading">
          <span>告警类型分布</span>
          <span>Pie + Bar Analysis</span>
        </div>
        <div ref="distributionRef" class="chart-canvas distribution-canvas"></div>
      </article>
    </div>
  </section>
</template>
