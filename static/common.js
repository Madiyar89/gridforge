// Общее для всех страниц GridForge — ключ, вызов API, toast, шапка с
// навигацией. Каждый раздел (Дашборд/Инвентарь/Шаблоны/Каналы) — свой
// .html + свой <раздел>.js, эти хелперы подключаются на каждой странице
// первым скриптом.

const KEY_STORAGE = "gridforge_api_key";
const REFRESH_MS = 5000;

const NAV_ITEMS = [
  { href: "index.html", label: "Дашборд" },
  { href: "inventory.html", label: "Инвентарь" },
  { href: "templates.html", label: "Шаблоны" },
  { href: "backups.html", label: "Бэкапы" },
  { href: "audit.html", label: "Аудит" },
  { href: "scan.html", label: "Скан" },
  { href: "console.html", label: "Консоль" },
  { href: "ad-audit.html", label: "AD-аудит" },
  { href: "syslog.html", label: "Syslog" },
  { href: "capture.html", label: "Трафик" },
  { href: "channels.html", label: "Каналы" },
];

function apiKey() {
  return localStorage.getItem(KEY_STORAGE) || "";
}

function escapeHtml(s) {
  const div = document.createElement("div");
  div.textContent = s ?? "";
  return div.innerHTML;
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      "X-API-Key": apiKey(),
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const err = new Error(body.detail || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  if (res.status === 204) return null;
  return res.json();
}

function toast(message, isError = false) {
  const el = document.getElementById("toast");
  if (!el) return;
  el.textContent = message;
  el.className = "toast show" + (isError ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove("show"), 3500);
}

function timeAgo(iso) {
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return `${seconds}с назад`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}м назад`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}ч назад`;
  return `${Math.floor(seconds / 86400)}д назад`;
}

function emptyOrError(e) {
  return e && e.status === 401 ? "введи API-ключ выше" : escapeHtml(e?.message || "ошибка");
}

async function updateRolePill() {
  const pill = document.getElementById("role-pill");
  if (!pill) return;
  if (!apiKey()) {
    pill.textContent = "не авторизован";
    pill.className = "role-pill";
    return;
  }
  try {
    await api("/api/nodes");
  } catch (e) {
    pill.textContent = "неверный ключ";
    pill.className = "role-pill bad";
    return;
  }
  try {
    await api("/api/api-keys");
    pill.textContent = "admin";
    pill.className = "role-pill ok";
  } catch (e) {
    pill.textContent = "viewer";
    pill.className = "role-pill";
  }
}

function initTopbar() {
  const nav = document.getElementById("nav");
  if (nav) {
    const here = location.pathname.split("/").pop() || "index.html";
    nav.innerHTML = NAV_ITEMS.map(
      (item) => `<a href="${item.href}" class="${item.href === here ? "active" : ""}">${item.label}</a>`
    ).join("");
  }

  const saveBtn = document.getElementById("save-key");
  if (saveBtn) {
    saveBtn.addEventListener("click", () => {
      const input = document.getElementById("api-key-input");
      const val = input.value.trim();
      if (!val) return;
      localStorage.setItem(KEY_STORAGE, val);
      input.value = "";
      toast("Ключ сохранён");
      updateRolePill();
      if (typeof onKeySaved === "function") onKeySaved();
    });
  }
  const input = document.getElementById("api-key-input");
  if (input && apiKey()) {
    input.placeholder = "ключ сохранён — заменить?";
  }
  updateRolePill();
}

document.addEventListener("DOMContentLoaded", initTopbar);
