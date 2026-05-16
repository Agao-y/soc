import { createRouter, createWebHistory } from "vue-router";
import { isAuthenticated } from "./auth";
import AlertFlowAnalysisPage from "./views/AlertFlowAnalysisPage.vue";
import DashboardPage from "./views/DashboardPage.vue";
import LoginPage from "./views/LoginPage.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: LoginPage,
    },
    {
      path: "/",
      name: "dashboard",
      component: DashboardPage,
      meta: { requiresAuth: true },
    },
    {
      path: "/alert-flow",
      name: "alert-flow-analysis",
      component: AlertFlowAnalysisPage,
      meta: { requiresAuth: true },
    },
  ],
});

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !isAuthenticated()) {
    return "/login";
  }
  if (to.path === "/login" && isAuthenticated()) {
    return "/";
  }
  return true;
});

export default router;
