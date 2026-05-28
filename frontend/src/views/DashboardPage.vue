<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import AiAnalysisBoard from "../components/AiAnalysisBoard.vue";
import AlertFlowTicker from "../components/AlertFlowTicker.vue";
import CockpitHeader from "../components/CockpitHeader.vue";
import ExplainabilityPanel from "../components/ExplainabilityPanel.vue";
import ResponseAdvicePanel from "../components/ResponseAdvicePanel.vue";
import SituationVisualizationPanel from "../components/SituationVisualizationPanel.vue";
import TicketFlowPanel from "../components/TicketFlowPanel.vue";
import {
  type Alert,
  type AlertDetail,
  type DashboardData,
  type Explainability,
  type IncidentItem,
  type UserInfo,
  fetchAlertDetail,
  fetchAlerts,
  fetchDashboard,
  fetchExplainability,
  fetchIncidents,
  fetchMe,
  fetchUsers,
  registerUser,
} from "../api/client";
import { clearAuth } from "../auth";

const router = useRouter();
const alerts = ref<Alert[]>([]);
const dashboard = ref<DashboardData | null>(null);
const selectedAlertId = ref("");
const detail = ref<AlertDetail | null>(null);
const explainability = ref<Explainability | null>(null);
const loading = ref(false);
const isFullscreen = ref(false);
const page = ref(1);
const totalPages = ref(1);
const pageSize = 20;
const viewMode = ref<"alerts" | "incidents">("alerts");
const incidents = ref<IncidentItem[]>([]);
const showUserModal = ref(false);
const users = ref<UserInfo[]>([]);
const newUsername = ref("");
const newPassword = ref("");
const registerError = ref("");
const registerOk = ref("");
const userRole = ref("");

let rotateTimer: number | undefined;
let pollTimer: number | undefined;

const selectedAlert = computed(() => alerts.value.find((item) => item.id === selectedAlertId.value) ?? null);

async function loadInitialData() {
  loading.value = true;
  try {
    const [dashboardData, alertData] = await Promise.all([
      fetchDashboard(),
      fetchAlerts(page.value, pageSize),
    ]);
    dashboard.value = dashboardData;
    alerts.value = alertData.items;
    totalPages.value = alertData.total_pages;
    selectedAlertId.value = alertData.items[0]?.id ?? "";
    loadIncidents();  // fire-and-forget
    fetchMe().then((u) => { userRole.value = u.role; }).catch(() => {});
  } finally {
    loading.value = false;
  }
}

async function goPage(p: number) {
  if (p < 1 || p > totalPages.value || p === page.value) return;
  page.value = p;
  loading.value = true;
  try {
    const alertData = await fetchAlerts(page.value, pageSize);
    alerts.value = alertData.items;
    totalPages.value = alertData.total_pages;
    selectedAlertId.value = alertData.items[0]?.id ?? "";
  } finally {
    loading.value = false;
  }
}

async function loadAlertContext(alertId: string) {
  detail.value = null;        // 立即清空旧数据，显示加载态
  explainability.value = null;
  loading.value = true;
  try {
    const [detailData, explainData] = await Promise.all([
      fetchAlertDetail(alertId),
      fetchExplainability(alertId),
    ]);
    detail.value = detailData;
    explainability.value = explainData;
  } catch {
    detail.value = null;
  } finally {
    loading.value = false;
  }
}

function handleSelect(alertId: string) {
  selectedAlertId.value = alertId;
  startRotation(); // 手动选择后重置轮播计时，避免被立即覆盖
}

function startRotation() {
  stopRotation();
  rotateTimer = window.setInterval(() => {
    if (!alerts.value.length) return;
    const currentIndex = alerts.value.findIndex((item) => item.id === selectedAlertId.value);
    const nextIndex = currentIndex >= 0 ? (currentIndex + 1) % alerts.value.length : 0;
    selectedAlertId.value = alerts.value[nextIndex].id;
  }, 6000);
}

function stopRotation() {
  if (rotateTimer) {
    window.clearInterval(rotateTimer);
    rotateTimer = undefined;
  }
}

async function loadIncidents() {
  try {
    const data = await fetchIncidents(10);
    incidents.value = data.incidents;
  } catch { /* ignore */ }
}

async function pollRefresh() {
  try {
    const [dashboardData, alertData] = await Promise.all([
      fetchDashboard(),
      fetchAlerts(page.value, pageSize),
    ]);
    dashboard.value = dashboardData;
    alerts.value = alertData.items;
    totalPages.value = alertData.total_pages;
    if (!alertData.items.find((a) => a.id === selectedAlertId.value)) {
      selectedAlertId.value = alertData.items[0]?.id ?? "";
    }
  } catch {
    // 轮询静默失败
  }
}

async function toggleFullscreen() {
  if (!document.fullscreenElement) {
    await document.documentElement.requestFullscreen();
    isFullscreen.value = true;
    return;
  }
  await document.exitFullscreen();
  isFullscreen.value = false;
}

function logout() {
  clearAuth();
  router.push("/login");
}

async function openUserModal() {
  registerError.value = "";
  registerOk.value = "";
  newUsername.value = "";
  newPassword.value = "";
  try {
    users.value = await fetchUsers();
  } catch {
    users.value = [];
  }
  showUserModal.value = true;
}

async function handleRegister() {
  registerError.value = "";
  registerOk.value = "";
  const u = newUsername.value.trim();
  const p = newPassword.value.trim();
  if (!u || !p) {
    registerError.value = "用户名和密码不能为空";
    return;
  }
  if (p.length < 8) {
    registerError.value = "密码至少8位";
    return;
  }
  try {
    await registerUser(u, p);
    registerOk.value = `用户 ${u} 创建成功`;
    newUsername.value = "";
    newPassword.value = "";
    users.value = await fetchUsers();
  } catch (e: any) {
    registerError.value = e?.response?.data?.detail ?? "创建失败";
  }
}

watch(selectedAlertId, (alertId) => {
  if (alertId) {
    void loadAlertContext(alertId);
  }
});

onMounted(async () => {
  await loadInitialData();
  startRotation();
  pollTimer = window.setInterval(pollRefresh, 30000);
});

onBeforeUnmount(() => {
  stopRotation();
  if (pollTimer) {
    window.clearInterval(pollTimer);
    pollTimer = undefined;
  }
});
</script>

<template>
  <div class="page-shell">
    <div class="grid-overlay"></div>
    <div class="ambient ambient-one"></div>
    <div class="ambient ambient-two"></div>
    <div class="ambient ambient-three"></div>

    <main class="dashboard-layout">
      <section class="hero-bar">
        <div>
          <p class="eyebrow">AI-Driven Advanced Threat Detection</p>
          <h1>龙王守护者-基于LLM的SIME告警智能分析平台</h1>
          <p class="hero-copy">
            以 SIEM 日志为底座，结合机器学习与大语言模型完成实时告警聚合、威胁研判、处置建议和工单闭环。
          </p>
        </div>
        <div class="hero-actions">
          <div class="hero-status">
            <span class="status-dot"></span>
            <span>LLM 分析链路在线</span>
          </div>
          <button v-if="userRole === 'admin'" class="hero-button" @click="openUserModal">用户管理</button>
          <button class="hero-button" @click="toggleFullscreen">
            {{ isFullscreen ? "退出全屏" : "全屏展示" }}
          </button>
          <button class="hero-button hero-button-ghost" @click="logout">退出登录</button>
        </div>
      </section>

      <CockpitHeader :dashboard="dashboard" />

      <section class="board-grid">
        <div class="grid-card area-visual">
          <SituationVisualizationPanel :dashboard="dashboard" />
        </div>
        <div class="grid-card area-analysis">
          <AiAnalysisBoard :detail="detail" :selected-alert="selectedAlert" :loading="loading" @status-changed="loadInitialData" />
        </div>
        <div class="grid-card area-alerts">
          <div class="panel-heading alert-view-header">
            <h2>{{ viewMode === "alerts" ? "实时告警流" : "攻击事件聚合" }}</h2>
            <div class="view-toggle">
              <button class="toggle-btn" :class="{ active: viewMode === 'alerts' }" @click="viewMode = 'alerts'">原始告警</button>
              <button class="toggle-btn" :class="{ active: viewMode === 'incidents' }" @click="viewMode = 'incidents'">聚合事件</button>
            </div>
          </div>

          <template v-if="viewMode === 'alerts'">
            <AlertFlowTicker
              :alerts="alerts"
              :selected-alert-id="selectedAlertId"
              :show-link-button="true"
              @select="handleSelect"
            />
            <div class="pager">
              <button class="pager-btn" :disabled="page <= 1" @click="goPage(page - 1)">上一页</button>
              <span class="pager-info">{{ page }} / {{ totalPages }}</span>
              <button class="pager-btn" :disabled="page >= totalPages" @click="goPage(page + 1)">下一页</button>
            </div>
          </template>

          <div v-else class="incident-list">
            <div v-if="incidents.length === 0" class="empty-state">正在加载聚合数据...</div>
            <div
              v-for="inc in incidents"
              :key="inc.source_ip"
              class="incident-card"
            >
              <div class="incident-top">
                <strong class="incident-ip">{{ inc.source_ip }}</strong>
                <span class="incident-badge">{{ inc.count }} 次</span>
              </div>
              <div class="incident-meta">
                <span>{{ inc.location }}</span>
                <span v-if="inc.severities.critical">高危 {{ inc.severities.critical }}</span>
                <span v-if="inc.severities.high">警告 {{ inc.severities.high }}</span>
                <span v-if="inc.severities.medium">中危 {{ inc.severities.medium }}</span>
                <span v-if="inc.severities.low">低危 {{ inc.severities.low }}</span>
              </div>
              <div v-if="inc.key_alerts.length" class="key-alerts">
                <div
                  v-for="ka in inc.key_alerts"
                  :key="ka.id"
                  class="key-alert-row"
                  :class="'key-sev-' + ka.severity"
                >
                  <span class="key-sev-tag">{{ ka.severity === 'critical' ? '严重' : ka.severity === 'high' ? '高危' : ka.severity === 'medium' ? '中危' : '低危' }}</span>
                  <span class="key-title">{{ ka.title }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div class="grid-card area-response">
          <ResponseAdvicePanel :detail="detail" :loading="loading" />
        </div>
        <div class="grid-card area-explain">
          <ExplainabilityPanel :explainability="explainability" :loading="loading" />
        </div>
        <div class="grid-card area-ticket">
          <TicketFlowPanel :dashboard="dashboard" />
        </div>
      </section>
    </main>

    <Teleport to="body">
      <div v-if="showUserModal" class="modal-backdrop" @click.self="showUserModal = false">
        <div class="modal-panel">
          <div class="modal-header">
            <h2>用户管理</h2>
            <button class="modal-close" @click="showUserModal = false">&times;</button>
          </div>

          <div class="modal-body">
            <div class="user-register-form">
              <h3>创建新用户</h3>
              <div class="register-row">
                <input
                  v-model="newUsername"
                  class="modal-input"
                  placeholder="用户名"
                  @keyup.enter="handleRegister"
                />
                <input
                  v-model="newPassword"
                  class="modal-input"
                  type="password"
                  placeholder="密码（至少8位）"
                  @keyup.enter="handleRegister"
                />
                <button class="modal-btn modal-btn-primary" @click="handleRegister">创建</button>
              </div>
              <p v-if="registerError" class="modal-msg modal-msg-error">{{ registerError }}</p>
              <p v-if="registerOk" class="modal-msg modal-msg-ok">{{ registerOk }}</p>
            </div>

            <div class="user-list">
              <h3>现有用户 ({{ users.length }})</h3>
              <div v-if="users.length === 0" class="empty-state">暂无用户数据</div>
              <div v-for="u in users" :key="u.username" class="user-row">
                <span class="user-name">{{ u.username }}</span>
                <span class="user-role" :class="{ 'role-admin': u.role === 'admin' }">{{ u.role }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
