import { API_URL } from './config.js';

const KEY = 'fs_auth';
export const auth = {
  get() { try { return JSON.parse(localStorage.getItem(KEY)); } catch { return null; } },
  set(v) { localStorage.setItem(KEY, JSON.stringify(v)); },
  clear() { localStorage.removeItem(KEY); },
};

export async function api(path, { method = 'GET', body } = {}) {
  const a = auth.get();
  const res = await fetch(API_URL + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(a?.token ? { Authorization: `Bearer ${a.token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = res.status === 204 ? null : await res.json().catch(() => null);
  if (!res.ok) {
    if (res.status === 401) auth.clear();
    throw Object.assign(new Error(data?.message || data?.error || `Ошибка ${res.status}`), { status: res.status });
  }
  return data;
}

// Пускает на страницу только с нужной ролью, иначе отправляет на вход
export function requireRole(roles, loginPage) {
  const a = auth.get();
  if (!a?.token || (roles && !roles.includes(a.user?.role))) { location.replace(loginPage); return null; }
  return a;
}

export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function say(el, text, ok = false) {
  el.textContent = text;
  el.className = 'note ' + (ok ? 'ok' : 'err');
  el.hidden = !text;
}

export function logout(loginPage) { auth.clear(); location.replace(loginPage); }
