<script setup lang="ts">
import { computed } from "vue";
import { useRouter } from "vue-router";
import type { Alert } from "../api/client";

const props = withDefaults(
  defineProps<{
    alerts: Alert[];
    selectedAlertId: string;
    showLinkButton?: boolean;
  }>(),
  {
    showLinkButton: false,
  },
);

defineEmits<{
  select: [alertId: string];
}>();

const router = useRouter();
const doubledAlerts = computed(() => [...props.alerts, ...props.alerts]);

const threatTypeLabel: Record<Alert["threat_type"], string> = {
  "brute-force": "暴力破解攻击",
  miner: "挖矿木马活动",
  ransomware: "勒索软件行为",
  c2: "C2 控制通信",
  "port-scan": "端口扫描攻击",
  exfiltration: "数据渗出风险",
};

function colorClass(level: Alert["severity"]) {
  return {
    critical: "severity-critical",
    high: "severity-high",
    medium: "severity-medium",
    low: "severity-low",
  }[level];
}

function scoreBySeverity(level: Alert["severity"]) {
  return {
    critical: 96,
    high: 84,
    medium: 63,
    low: 32,
  }[level];
}
</script>

<template>
  <section class="panel panel-accent-cyan ticker-panel">
    <div class="panel-heading">
      <h2>实时告警流</h2>
      <span class="panel-tag">Streaming Alerts</span>
    </div>

    <div v-if="showLinkButton" class="ticker-action-row">
      <button class="hero-button ticker-link-button" @click="router.push('/alert-flow')">
        进入实时告警流分析页
      </button>
    </div>

    <div class="ticker-viewport">
      <div class="ticker-track">
        <button
          v-for="(alert, index) in doubledAlerts"
          :key="`${alert.id}-${index}`"
          class="ticker-card"
          :class="[colorClass(alert.severity), { active: selectedAlertId === alert.id }]"
          @click="$emit('select', alert.id)"
        >
          <div class="ticker-topline">
            <span>{{ new Date(alert.timestamp).toLocaleTimeString("zh-CN", { hour12: false }) }}</span>
            <span>{{ alert.source_ip }}</span>
          </div>
          <strong>{{ threatTypeLabel[alert.threat_type] }}</strong>
          <div class="ticker-bottomline">
            <span>{{ alert.destination_ip }} · {{ alert.event_type }}</span>
            <span>Risk {{ scoreBySeverity(alert.severity) }}</span>
          </div>
        </button>
      </div>
    </div>
  </section>
</template>
