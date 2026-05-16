<script setup lang="ts">
import { computed } from "vue";
import type { DashboardData } from "../api/client";

const props = defineProps<{
  dashboard: DashboardData | null;
}>();

const points = computed(() =>
  (props.dashboard?.attack_map ?? []).map((point) => ({
    ...point,
    x: ((point.longitude + 180) / 360) * 100,
    y: ((90 - point.latitude) / 180) * 100,
  })),
);
</script>

<template>
  <section class="panel panel-accent-danger map-panel">
    <div class="panel-heading">
      <h2>攻击态势热力图</h2>
      <span class="panel-tag">Attack Source Map</span>
    </div>

    <div class="map-stage">
      <div class="world-grid"></div>
      <div
        v-for="point in points"
        :key="`${point.country}-${point.name}`"
        class="map-point"
        :style="{
          left: `${point.x}%`,
          top: `${point.y}%`,
          '--intensity': `${0.35 + point.intensity}`,
        }"
      >
        <span class="point-pulse"></span>
        <div class="point-label">{{ point.name }} · {{ point.attacks }}</div>
      </div>
    </div>
  </section>
</template>
