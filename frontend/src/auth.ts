import axios from "axios";

const AUTH_KEY = "soc-jwt-token";

export function isAuthenticated() {
  return localStorage.getItem(AUTH_KEY) !== null;
}

export function getToken(): string | null {
  return localStorage.getItem(AUTH_KEY);
}

export async function login(username: string, password: string) {
  const { data } = await axios.post("/api/auth/login", { username, password });
  localStorage.setItem(AUTH_KEY, data.access_token);
  return data.username;
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}
