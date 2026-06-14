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
  "brute-force": "暴力破解", miner: "挖矿活动", ransomware: "勒索行为",
  c2: "C2 控制", "port-scan": "端口扫描", exfiltration: "数据渗出",
  "web-attack": "Web攻击", "sql-injection": "SQL注入", xss: "XSS跨站",
  phishing: "钓鱼攻击", ddos: "DDoS拒绝服务", webshell: "Webshell上传",
  "privilege-escalation": "权限提升", "lateral-movement": "横向移动",
  "credential-dumping": "凭据转储",
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
