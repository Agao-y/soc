const AUTH_KEY = "soc-authenticated";
const DEFAULT_USERNAME = "admin";
const DEFAULT_PASSWORD = "admin123";

export function isAuthenticated() {
  return localStorage.getItem(AUTH_KEY) === "true";
}

export function login(username: string, password: string) {
  const ok = username === DEFAULT_USERNAME && password === DEFAULT_PASSWORD;
  if (ok) {
    localStorage.setItem(AUTH_KEY, "true");
  }
  return ok;
}

export function clearAuth() {
  localStorage.removeItem(AUTH_KEY);
}
