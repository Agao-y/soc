import axios from "axios";

const TOKEN_KEY = "soc-jwt-token";
const ROLE_KEY = "soc-user-role";

export function isAuthenticated() {
  return localStorage.getItem(TOKEN_KEY) !== null;
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function isAdmin() {
  return localStorage.getItem(ROLE_KEY) === "admin";
}

export async function login(username: string, password: string) {
  const { data } = await axios.post("/api/auth/login", { username, password });
  localStorage.setItem(TOKEN_KEY, data.access_token);
  localStorage.setItem(ROLE_KEY, data.role || "analyst");
  return data.username;
}

export function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(ROLE_KEY);
}
