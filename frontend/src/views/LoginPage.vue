<script setup lang="ts">
import { ref } from "vue";
import { useRouter } from "vue-router";
import { login } from "../auth";

const router = useRouter();
const username = ref("admin");
const password = ref("admin123");
const error = ref("");
const loading = ref(false);

async function submit() {
  error.value = "";
  loading.value = true;
  try {
    await login(username.value, password.value);
    router.push("/");
  } catch {
    error.value = "账号或密码错误";
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="page-shell page-shell-centered login-shell">
    <div class="grid-overlay"></div>
    <div class="ambient ambient-one"></div>
    <div class="ambient ambient-two"></div>
    <main class="login-layout">
      <section class="panel panel-accent-cyan login-panel">
        <p class="eyebrow">Secure Access</p>
        <h1 class="login-title">登录龙王守护者</h1>
        <p class="hero-copy login-copy">
          请输入账号密码进入“龙王守护者-基于LLM的SIME告警智能分析平台”。
        </p>

        <div class="login-form">
          <label class="login-label">
            <span>账号</span>
            <input v-model="username" class="login-input" type="text" autocomplete="username" />
          </label>
          <label class="login-label">
            <span>密码</span>
            <input v-model="password" class="login-input" type="password" autocomplete="current-password" />
          </label>
          <button class="hero-button login-button" @click="submit" :disabled="loading">
            {{ loading ? "登录中..." : "进入系统" }}
          </button>
          <p v-if="error" class="login-error">{{ error }}</p>
          <p class="login-tip">默认账号：`admin` 默认密码：`admin123`</p>
        </div>
      </section>
    </main>
  </div>
</template>
