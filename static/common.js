// Общее для всех страниц GridForge — ключ, вызов API, toast, шапка с
// навигацией. Каждый раздел (Дашборд/Инвентарь/Шаблоны/Каналы) — свой
// .html + свой <раздел>.js, эти хелперы подключаются на каждой странице
// первым скриптом.

const KEY_STORAGE = "gridforge_api_key";
const REFRESH_MS = 5000;

// Иконки рисуем сами, без библиотеки: сторонние скрипты и шрифты сюда
// всё равно не загрузить (страница отдаётся с локального сервера без
// интернета), а тринадцати простых значков это не стоит.
// Один стиль на все: контур 1.6px, сетка 20x20, без заливки.
const NAV_ICONS = {
  dashboard: '<rect x="3" y="3" width="6.5" height="6.5" rx="1"/><rect x="10.5" y="3" width="6.5" height="6.5" rx="1"/><rect x="3" y="10.5" width="6.5" height="6.5" rx="1"/><rect x="10.5" y="10.5" width="6.5" height="6.5" rx="1"/>',
  inventory: '<rect x="3" y="3.5" width="14" height="4.5" rx="1"/><rect x="3" y="12" width="14" height="4.5" rx="1"/><circle cx="6" cy="5.75" r=".6"/><circle cx="6" cy="14.25" r=".6"/>',
  templates: '<path d="M10 2.5 17 6l-7 3.5L3 6z"/><path d="M3 10l7 3.5L17 10"/><path d="M3 14l7 3.5L17 14"/>',
  rubka: '<rect x="2.5" y="3.5" width="15" height="13" rx="1.5"/><path d="M5.5 8.5l2.5 2-2.5 2"/><path d="M10 12.5h4.5"/>',
  scenarios: '<path d="M6 2.5v15"/><path d="M14 2.5v15"/><path d="M6 6.5h8"/><path d="M6 10h8"/><path d="M6 13.5h8"/><path d="M3.5 4.5h2v2h-2z"/>',
  console: '<rect x="2.5" y="3.5" width="15" height="13" rx="1.5"/><path d="M6 7.5l3 2.5-3 2.5"/>',
  backups: '<path d="M3 6.5h14v9.5a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1z"/><path d="M2 3.5h16v3H2z"/><path d="M8 10h4"/>',
  audit: '<path d="M10 2.5 16.5 5v5c0 4-3 6.5-6.5 7.5C6.5 16.5 3.5 14 3.5 10V5z"/><path d="M7.5 9.8l1.8 1.8 3.2-3.4"/>',
  syslog: '<path d="M4 4.5h12"/><path d="M4 8h12"/><path d="M4 11.5h8"/><path d="M4 15h10"/>',
  scan: '<circle cx="9" cy="9" r="5.5"/><path d="M13.2 13.2 17 17"/>',
  capture: '<path d="M2.5 10.5h3l2-5 3 9 2.5-6 1.5 2h3"/>',
  adaudit: '<circle cx="7.5" cy="7" r="2.8"/><path d="M2.5 16c0-2.8 2.2-4.5 5-4.5s5 1.7 5 4.5"/><path d="M13.5 8.5l1.6 1.6 2.4-2.6"/>',
  channels: '<path d="M10 3a4.5 4.5 0 0 1 4.5 4.5c0 3.5 1.5 5 1.5 5H4s1.5-1.5 1.5-5A4.5 4.5 0 0 1 10 3z"/><path d="M8.3 15.5a1.8 1.8 0 0 0 3.4 0"/>',
  ports: '<rect x="2.5" y="5.5" width="15" height="9" rx="1.5"/><path d="M6 8.5v3"/><path d="M10 8.5v3"/><path d="M14 8.5v3"/>',
  users: '<circle cx="10" cy="6.5" r="3"/><path d="M4 16.5c0-3.2 2.7-5 6-5s6 1.8 6 5"/>',
  credentials: '<circle cx="7" cy="10" r="3.5"/><path d="M10.2 10h7.3"/><path d="M14.5 10v3"/><path d="M17 10v2.2"/>',
};

function navIcon(name) {
  return (
    `<svg class="nav-icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" ` +
    `stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` +
    `${NAV_ICONS[name] || ""}</svg>`
  );
}

// Разделы сгруппированы по смыслу: плоский список из 13 пунктов
// приходится перечитывать целиком, чтобы найти нужный.
const NAV_GROUPS = [
  {
    title: null, // Дашборд — без заголовка, он один
    items: [{ href: "index.html", label: "Дашборд", icon: "dashboard" }],
  },
  {
    title: "Сеть",
    items: [
      { href: "inventory.html", label: "Инвентарь", icon: "inventory" },
      { href: "templates.html", label: "Шаблоны", icon: "templates" },
      { href: "rubka.html", label: "Рубка", icon: "rubka" },
      { href: "scenarios.html", label: "Сценарии", icon: "scenarios" },
      { href: "ports.html", label: "Порты", icon: "ports" },
      { href: "console.html", label: "Консоль", icon: "console" },
    ],
  },
  {
    title: "Состояние",
    items: [
      { href: "backups.html", label: "Бэкапы", icon: "backups" },
      { href: "audit.html", label: "Аудит", icon: "audit" },
      { href: "syslog.html", label: "Syslog", icon: "syslog" },
    ],
  },
  {
    title: "Разведка",
    items: [
      { href: "scan.html", label: "Скан", icon: "scan" },
      { href: "capture.html", label: "Трафик", icon: "capture" },
      { href: "ad-audit.html", label: "AD-аудит", icon: "adaudit" },
    ],
  },
  {
    title: "Настройки",
    items: [
      { href: "channels.html", label: "Каналы", icon: "channels" },
      { href: "users.html", label: "Пользователи", icon: "users" },
      { href: "credentials.html", label: "Учётки", icon: "credentials" },
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

// Естественная сортировка имён узлов: "LAB-2" перед "LAB-10" —
// обычное лексикографическое сравнение (то, что отдаёт API, ORDER BY
// name) ставит "LAB-10" раньше "LAB-2". Здесь строка режется на
// числовые/нечисловые куски, и числа сравниваются как числа, а не
// посимвольно. Общая для всех страниц со списком/выпадающим списком
// узлов (Рубка, Сценарии, Инвентарь, Порты, Консоль, Бэкапы, Аудит...).
function naturalCompare(a, b) {
  const ax = String(a).match(/\d+|\D+/g) || [];
  const bx = String(b).match(/\d+|\D+/g) || [];
  const len = Math.max(ax.length, bx.length);
  for (let i = 0; i < len; i++) {
    const av = ax[i] ?? "";
    const bv = bx[i] ?? "";
    if (av === bv) continue;
    const an = Number(av);
    const bn = Number(bv);
    if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== "" && bv !== "") {
      if (an !== bn) return an - bn;
    }
    return av < bv ? -1 : 1;
  }
  return 0;
}

function sortNodesNatural(nodes) {
  return [...nodes].sort((a, b) => naturalCompare(a.name, b.name));
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

// Учётка узла централизована (Credential, Настройки → Учётки) — большинство
// запросов к устройствам (бэкап, порты, Рубка, Сценарии, консоль) шлётся
// БЕЗ username/password, сервер сам подставляет центральную учётку по
// группе узла. Просим логин/пароль вручную только если сервер ответил, что
// подходящей учётки нет (422, credentialRequired) — тогда одна попытка
// повтора с введённой учёткой, без сохранения на клиенте.
async function apiWithCredentials(path, options = {}) {
  try {
    return await api(path, options);
  } catch (e) {
    if (e.status !== 422 || !/нужен логин/.test(e.message)) throw e;
    const username = prompt("Логин для подключения к узлу (учётка по умолчанию не настроена):");
    if (!username) throw e;
    const password = prompt("Пароль (пусто — если вход по ключу):") || null;
    const body = options.body ? JSON.parse(options.body) : {};
    body.username = username;
    body.password = password;
    return await api(path, { ...options, body: JSON.stringify(body) });
  }
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
                `<a href="${item.href}" class="${item.href === here ? "active" : ""}" title="${item.label}">` +
                `${navIcon(item.icon)}<span class="nav-label">${item.label}</span></a>`
            )
            .join("")}
        </div>`
    ).join("");
  }
  setupNavToggle();

  // Название режем на первую букву и хвост: в свёрнутой панели виден
  // только «G», при наведении дорисовывается остальное.
  const brandName = document.querySelector(".brand b");
  if (brandName && !brandName.querySelector(".brand-rest")) {
    const full = brandName.textContent;
    brandName.innerHTML = `${full.slice(0, 1)}<span class="brand-rest">${full.slice(1)}</span>`;
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
  requireAuth();
}

document.addEventListener("DOMContentLoaded", initTopbar);
