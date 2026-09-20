// Общее для всех страниц GridForge — ключ, вызов API, toast, шапка с
// навигацией. Каждый раздел (Дашборд/Инвентарь/Шаблоны/Каналы) — свой
// .html + свой <раздел>.js, эти хелперы подключаются на каждой странице
// первым скриптом.

const KEY_STORAGE = "gridforge_api_key";
const REFRESH_MS = 5000;

// Разделы сгруппированы по смыслу: плоский список из 13 пунктов
// приходится перечитывать целиком, чтобы найти нужный.
const NAV_GROUPS = [
  {
    title: null, // Дашборд — без заголовка, он один
    items: [{ href: "index.html", label: "Дашборд" }],
  },
  {
    title: "Сеть",
    items: [
      { href: "inventory.html", label: "Инвентарь" },
      { href: "templates.html", label: "Шаблоны" },
      { href: "rubka.html", label: "Рубка" },
      { href: "console.html", label: "Консоль" },
    ],
  },
  {
    title: "Состояние",
    items: [
      { href: "backups.html", label: "Бэкапы" },
      { href: "audit.html", label: "Аудит" },
      { href: "syslog.html", label: "Syslog" },
    ],
  },
  {
    title: "Разведка",
    items: [
      { href: "scan.html", label: "Скан" },
      { href: "capture.html", label: "Трафик" },
      { href: "ad-audit.html", label: "AD-аудит" },
    ],
  },
  {
    title: "Настройки",
    items: [
      { href: "channels.html", label: "Каналы" },
      { href: "users.html", label: "Пользователи" },
    ],
  },
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
  let me;
  try {
    me = await api("/api/whoami");
  } catch (e) {
    pill.textContent = "неверный ключ";
    pill.className = "role-pill bad";
    return;
  }
  pill.textContent = me.kind === "user" ? `${me.label} · ${me.role}` : me.role;
  pill.className = me.role === "admin" ? "role-pill ok" : "role-pill";
  if (me.kind === "user") showLogoutButton();
  if (me.default_password) showDefaultPasswordWarning();
}

// Вход по паролю и по API-ключу существуют параллельно: ключ нужен
// программам, пароль — людям. Отправляем на страницу входа, когда не
// работает НИ ОДИН из них.
//
// Проверять надо именно так, а не «есть ли сохранённый ключ»: с
// протухшим ключом в localStorage страница показывала «неверный ключ» и
// никуда не вела — войти паролем было неоткуда, пока не почистишь
// хранилище руками. Найдено на живом ноутбуке владельца.
async function requireAuth() {
  try {
    await api("/api/whoami");
  } catch (e) {
    if (e.status !== 401) return;
    // Ключ больше не действует — убираем, иначе он продолжит подменять
    // собой вход по паролю на всех страницах.
    if (apiKey()) localStorage.removeItem(KEY_STORAGE);
    window.location.href = "login.html";
  }
}

function showLogoutButton() {
  if (document.getElementById("logout-btn")) return;
  const keybox = document.querySelector(".keybox");
  if (!keybox) return;
  // Вошли по паролю — поле для ручного ключа только мешает.
  keybox.innerHTML = `<button id="logout-btn">Выйти</button>`;
  document.getElementById("logout-btn").addEventListener("click", async () => {
    await fetch("/api/logout", { method: "POST" });
    window.location.href = "login.html";
  });
}

function showDefaultPasswordWarning() {
  if (document.getElementById("default-password-warning")) return;
  const banner = document.createElement("div");
  banner.id = "default-password-warning";
  banner.style.cssText =
    "background:#7a2d2d;color:#fff;padding:10px 16px;font-size:13px;text-align:center;";
  banner.innerHTML =
    "Стоит пароль по умолчанию (<b>Admin</b>/<b>gridforge</b>) — он общеизвестен. " +
    "Смени его: <b>Пользователи → сменить пароль</b>.";
  document.body.insertBefore(banner, document.body.firstChild);
}

// На узком экране панель уезжает за край и открывается кнопкой —
// фиксированная колонка съела бы пол-экрана телефона.
function setupNavToggle() {
  if (document.getElementById("nav-toggle")) return;
  const bar = document.querySelector(".topbar");
  if (!bar) return;
  const btn = document.createElement("button");
  btn.id = "nav-toggle";
  btn.className = "nav-toggle";
  btn.textContent = "☰";
  btn.setAttribute("aria-label", "Меню");
  btn.addEventListener("click", () => bar.classList.toggle("open"));
  document.body.appendChild(btn);
  // Клик по ссылке закрывает меню: иначе оно остаётся поверх страницы,
  // на которую только что перешли.
  bar.querySelectorAll(".nav a").forEach((a) =>
    a.addEventListener("click", () => bar.classList.remove("open"))
  );
}

function initTopbar() {
  const nav = document.getElementById("nav");
  if (nav) {
    const here = location.pathname.split("/").pop() || "index.html";
    nav.innerHTML = NAV_GROUPS.map(
      (group) => `
        <div class="nav-group">
          ${group.title ? `<div class="nav-group-title">${group.title}</div>` : ""}
          ${group.items
            .map(
              (item) =>
                `<a href="${item.href}" class="${item.href === here ? "active" : ""}">${item.label}</a>`
            )
            .join("")}
        </div>`
    ).join("");
  }
  setupNavToggle();

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
  requireAuth();
}

document.addEventListener("DOMContentLoaded", initTopbar);
