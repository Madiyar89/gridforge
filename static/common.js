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
  netaudit: '<path d="M4 4.5h12v6.5H4z"/><path d="M7 14h6"/><path d="M10 11v3"/><path d="M13.5 7l1.6 1.6 2.4-2.6"/>',
  configsearch: '<circle cx="8.5" cy="8.5" r="5"/><path d="M12.5 12.5 17 17"/><path d="M6 8.5h5"/>',
  hubs: '<circle cx="10" cy="4.5" r="2"/><circle cx="4" cy="15.5" r="2"/><circle cx="16" cy="15.5" r="2"/><path d="M10 6.5v3"/><path d="M10 9.5 4 13.5"/><path d="M10 9.5l6 4"/>',
  macsearch: '<rect x="3" y="8" width="14" height="5" rx="1"/><path d="M6 8V5.5h8V8"/><circle cx="7" cy="10.5" r=".6"/><path d="M13 13v2.5"/>',
  domainscan: '<rect x="3" y="4" width="14" height="9" rx="1.5"/><path d="M7 16.5h6"/><path d="M10 13v3.5"/><circle cx="10" cy="8.5" r="2"/>',
  commandsref: '<path d="M4 3.5h9l3 3v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-12a1 1 0 0 1 1-1z"/><path d="M6.5 8.5h7"/><path d="M6.5 11.5h7"/><path d="M6.5 14.5h4"/>',
  firmware: '<rect x="4" y="3" width="12" height="14" rx="1.5"/><path d="M7.5 7h5"/><path d="M7.5 10h5"/><circle cx="10" cy="14" r="1.2"/>',
  channels: '<path d="M10 3a4.5 4.5 0 0 1 4.5 4.5c0 3.5 1.5 5 1.5 5H4s1.5-1.5 1.5-5A4.5 4.5 0 0 1 10 3z"/><path d="M8.3 15.5a1.8 1.8 0 0 0 3.4 0"/>',
  ports: '<rect x="2.5" y="5.5" width="15" height="9" rx="1.5"/><path d="M6 8.5v3"/><path d="M10 8.5v3"/><path d="M14 8.5v3"/>',
  users: '<circle cx="10" cy="6.5" r="3"/><path d="M4 16.5c0-3.2 2.7-5 6-5s6 1.8 6 5"/>',
  credentials: '<circle cx="7" cy="10" r="3.5"/><path d="M10.2 10h7.3"/><path d="M14.5 10v3"/><path d="M17 10v2.2"/>',
  integrations: '<circle cx="5.5" cy="5.5" r="2.3"/><circle cx="14.5" cy="5.5" r="2.3"/><circle cx="5.5" cy="14.5" r="2.3"/><circle cx="14.5" cy="14.5" r="2.3"/><path d="M7.6 5.5h4.6"/><path d="M5.5 7.6v4.6"/><path d="M14.5 7.6v4.6"/>',
  ldap: '<rect x="3" y="4" width="14" height="4" rx="1"/><rect x="3" y="9" width="14" height="4" rx="1"/><rect x="3" y="14" width="14" height="2.5" rx="1"/><circle cx="6" cy="6" r=".6"/><circle cx="6" cy="11" r=".6"/>',
  vuln: '<path d="M10 2.5 16.5 5v5c0 4-3 6.5-6.5 7.5C6.5 16.5 3.5 14 3.5 10V5z"/><path d="M10 6.5v4.5"/><circle cx="10" cy="13.2" r=".7" fill="currentColor" stroke="none"/>',
  cables: '<path d="M3 15q3 0 3-4t4-4q4 0 4 4t3 4"/><circle cx="3" cy="15" r="1.3"/><circle cx="17" cy="15" r="1.3"/>',
  chevron: '<path d="M6 7.5 10 12l4-4.5"/>',
  // Значок зоны (группы) в свёрнутой рельсе — свой только для "Настроек",
  // у остальных групп переиспользован иконка первого/самого узнаваемого
  // пункта группы (см. NAV_GROUPS: icon), не плодим похожие значки.
  settingsgear: '<circle cx="10" cy="10" r="2.6"/><path d="M10 3.5v2.2M10 14.3v2.2M3.5 10h2.2M14.3 10h2.2M5.4 5.4l1.5 1.5M13.1 13.1l1.5 1.5M14.6 5.4l-1.5 1.5M6.9 13.1l-1.5 1.5"/>',
};

function navIcon(name, extraClass) {
  return (
    `<svg class="nav-icon${extraClass ? " " + extraClass : ""}" viewBox="0 0 20 20" fill="none" stroke="currentColor" ` +
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
    icon: "inventory",
    items: [
      { href: "inventory.html", label: "Инвентарь", icon: "inventory" },
      { href: "templates.html", label: "Шаблоны", icon: "templates" },
      { href: "rubka.html", label: "Рубка", icon: "rubka" },
      { href: "scenarios.html", label: "Сценарии", icon: "scenarios" },
      { href: "ports.html", label: "Порты", icon: "ports" },
      { href: "console.html", label: "Консоль", icon: "console" },
      { href: "commands.html", label: "Команды", icon: "commandsref" },
      { href: "firmware.html", label: "Версии ПО", icon: "firmware" },
    ],
  },
  {
    title: "Состояние",
    icon: "audit",
    items: [
      { href: "backups.html", label: "Бэкапы", icon: "backups" },
      { href: "audit.html", label: "Аудит", icon: "audit" },
      { href: "config-search.html", label: "Поиск по конфигу", icon: "configsearch" },
      { href: "hubs.html", label: "Вероятные хабы", icon: "hubs" },
      { href: "mac-search.html", label: "Поиск MAC", icon: "macsearch" },
      { href: "domain-scan.html", label: "Домен", icon: "domainscan" },
      { href: "syslog.html", label: "Syslog", icon: "syslog" },
    ],
  },
  {
    title: "Разведка",
    icon: "scan",
    items: [
      { href: "scan.html", label: "Скан", icon: "scan" },
      { href: "vuln.html", label: "Уязвимости", icon: "vuln" },
      { href: "cables.html", label: "Кабели", icon: "cables" },
      { href: "capture.html", label: "Трафик", icon: "capture" },
      { href: "ad-audit.html", label: "AD-аудит", icon: "adaudit" },
      { href: "network-audit.html", label: "Аудит сети", icon: "netaudit" },
    ],
  },
  {
    title: "Настройки",
    icon: "settingsgear",
    items: [
      { href: "channels.html", label: "Каналы", icon: "channels" },
      { href: "users.html", label: "Пользователи", icon: "users" },
      { href: "credentials.html", label: "Учётки", icon: "credentials" },
      { href: "integrations.html", label: "Интеграции", icon: "integrations" },
      { href: "ldap.html", label: "LDAP", icon: "ldap" },
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
  // Math.max(0, ...) — часы браузера и сервера не идеально синхронны
  // (реальный случай: клиент отстаёт от сервера на минуту-две), без
  // защиты разница уходит в минус и показывает бессмысленное "-93с назад".
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}с назад`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}м назад`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}ч назад`;
  return `${Math.floor(seconds / 86400)}д назад`;
}

function emptyOrError(e) {
  return e && e.status === 401 ? "введи API-ключ выше" : escapeHtml(e?.message || "ошибка");
}

function setAvatarState(letter, online) {
  const letterEl = document.querySelector("#user-avatar .user-avatar-letter");
  const dotEl = document.querySelector("#user-avatar .user-avatar-dot");
  if (letterEl) letterEl.textContent = letter;
  if (dotEl) dotEl.classList.toggle("on", online);
}

async function updateRolePill() {
  const pill = document.getElementById("role-pill");
  if (!pill) return;
  if (!apiKey()) {
    pill.textContent = "не авторизован";
    pill.className = "role-pill";
    setAvatarState("?", false);
    return;
  }
  let me;
  try {
    me = await api("/api/whoami");
  } catch (e) {
    pill.textContent = "неверный ключ";
    pill.className = "role-pill bad";
    setAvatarState("!", false);
    return;
  }
  pill.textContent = me.kind === "user" ? `${me.label} · ${me.role}` : me.role;
  pill.className = me.role === "admin" ? "role-pill ok" : "role-pill";
  const label = me.kind === "user" ? me.label : me.role;
  setAvatarState((label || "?").slice(0, 1).toUpperCase(), true);
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

// Закрепление развёрнутого состояния панели — явная кнопка-стрелка
// вместо наведения (см. .sidebar-pin в style.css и разбор источника
// infogra.ru, 2026-09-23: "стрелка влево — свернуть, вправо —
// развернуть"). Выбор запоминается в localStorage — на телефоне (см.
// .topbar.open, отдельный механизм для <820px) кнопка не показывается.
const SIDEBAR_PIN_KEY = "gridforge_sidebar_pinned";
const PIN_ARROW_SVG =
  '<svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" ' +
  'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.5 5l5 5-5 5"/></svg>';

function setPinned(next) {
  const bar = document.querySelector(".topbar");
  if (!bar) return;
  bar.classList.toggle("pinned", next);
  localStorage.setItem(SIDEBAR_PIN_KEY, next ? "1" : "0");
}

function setupSidebarPin() {
  const bar = document.querySelector(".topbar");
  if (!bar || document.getElementById("sidebar-pin")) return;
  setPinned(localStorage.getItem(SIDEBAR_PIN_KEY) === "1");

  const btn = document.createElement("button");
  btn.id = "sidebar-pin";
  btn.className = "sidebar-pin";
  btn.innerHTML = PIN_ARROW_SVG;
  btn.setAttribute("aria-label", "Закрепить панель развёрнутой");
  btn.addEventListener("click", () => setPinned(!bar.classList.contains("pinned")));
  bar.appendChild(btn);

  // По запросу пользователя (2026-09-24): не нужно отдельно нажимать
  // кнопку-стрелку, чтобы свернуть закреплённую панель — клик по любому
  // рабочему пункту (переход на страницу, что в самой рельсе, что во
  // флайауте зоны) сам её сворачивает. Клик по заголовку зоны
  // (аккордеон, без перехода) панель НЕ закрывает — там пользователь
  // ещё выбирает, куда идти. Делегирование на document, а не на nav:
  // флайаут — отдельный элемент в <body> (см. setupFloatingPopups),
  // пересоздаётся при каждом наведении, точечно вешать слушатель не на
  // чем.
  document.addEventListener("click", (e) => {
    if (e.target.closest(".nav a, .nav-flyout a")) setPinned(false);
  });
}

// Какие группы развёрнуты (аккордеон, по запросу пользователя 2026-09-23:
// "не удобно на все разом смотреть", пример — сворачивающиеся секции
// Zabbix). По умолчанию открыта только группа с текущей страницей —
// остальные не нужно листать глазами, чтобы найти нужный пункт.
// Работает только в закреплённой (pinned) развёрнутой панели: в узкой
// иконочной рельсе подписи группы всё равно не видно, сворачивать нечего.
const NAV_OPEN_GROUPS_KEY = "gridforge_nav_open_groups";

function loadOpenGroups(defaultTitle) {
  try {
    const raw = localStorage.getItem(NAV_OPEN_GROUPS_KEY);
    if (raw) return new Set(JSON.parse(raw));
  } catch (e) {
    /* битые данные в localStorage — просто откатимся к дефолту */
  }
  return new Set(defaultTitle ? [defaultTitle] : []);
}

function saveOpenGroups(set) {
  localStorage.setItem(NAV_OPEN_GROUPS_KEY, JSON.stringify([...set]));
}

// Флайаут группы и тултип одиночной иконки — вынесены в <body>
// ("портал") и управляются JS вместо чистого CSS :hover (2026-09-24,
// реальный баг: оба поп-апа раньше были потомками .topbar{overflow:
// hidden} с position:absolute и физически обрезались панелью — скорее
// всего вообще не показывались в браузере). Общие элементы на весь
// сайт: #floating-tooltip (для пунктов без группы) и #floating-flyout
// (для групп), создаются один раз и переиспользуются под текущий
// наведённый пункт. Раздельные таймеры показа/скрытия — задержка перед
// появлением (не мигать при быстром проходе мышью мимо) и перед
// исчезновением (успеть довести курсор до самого поп-апа).
function createPopupController(el, showDelay) {
  let showTimer = null;
  let hideTimer = null;
  return {
    show(positionAndFill) {
      clearTimeout(hideTimer);
      clearTimeout(showTimer);
      showTimer = setTimeout(() => {
        positionAndFill();
        el.classList.add("visible");
      }, showDelay);
    },
    cancelShow() {
      clearTimeout(showTimer);
    },
    scheduleHide() {
      clearTimeout(showTimer);
      hideTimer = setTimeout(() => el.classList.remove("visible"), 150);
    },
    cancelHide() {
      clearTimeout(hideTimer);
    },
  };
}

function setupFloatingPopups(nav) {
  let tooltipEl = document.getElementById("floating-tooltip");
  if (!tooltipEl) {
    tooltipEl = document.createElement("div");
    tooltipEl.id = "floating-tooltip";
    document.body.appendChild(tooltipEl);
  }
  let flyoutEl = document.getElementById("floating-flyout");
  if (!flyoutEl) {
    flyoutEl = document.createElement("div");
    flyoutEl.id = "floating-flyout";
    flyoutEl.className = "nav-flyout";
    document.body.appendChild(flyoutEl);
  }

  const tooltip = createPopupController(tooltipEl, 250);
  tooltipEl.addEventListener("mouseenter", tooltip.cancelHide);
  tooltipEl.addEventListener("mouseleave", tooltip.scheduleHide);

  nav.querySelectorAll("a[data-tooltip]").forEach((a) => {
    a.addEventListener("mouseenter", () => {
      const bar = document.querySelector(".topbar");
      if (!bar || bar.classList.contains("pinned")) return;
      tooltip.show(() => {
        const rect = a.getBoundingClientRect();
        tooltipEl.textContent = a.dataset.tooltip;
        tooltipEl.style.top = `${rect.top + rect.height / 2}px`;
        tooltipEl.style.left = `${rect.right + 10}px`;
      });
    });
    a.addEventListener("mouseleave", () => {
      tooltip.cancelShow();
      tooltip.scheduleHide();
    });
  });

  const flyout = createPopupController(flyoutEl, 100);
  flyoutEl.addEventListener("mouseenter", flyout.cancelHide);
  flyoutEl.addEventListener("mouseleave", flyout.scheduleHide);

  const here = location.pathname.split("/").pop() || "index.html";
  nav.querySelectorAll(".nav-group").forEach((group) => {
    const titleBtn = group.querySelector(".nav-group-title[data-group]");
    if (!titleBtn) return; // группа без заголовка (Дашборд) — флайаута нет
    const groupData = NAV_GROUPS.find((g) => g.title === titleBtn.dataset.group);
    if (!groupData) return;

    const showFlyout = (anchorEl) => {
      const bar = document.querySelector(".topbar");
      if (!bar) return;
      // Группа уже открыта инлайн в закреплённой панели — пункты и так
      // видны строками, второй флайаут поверх был бы лишним.
      if (bar.classList.contains("pinned") && titleBtn.classList.contains("open")) return;
      flyout.show(() => {
        flyoutEl.innerHTML =
          `<div class="nav-flyout-title">${escapeHtml(groupData.title)}</div>` +
          groupData.items
            .map(
              (item) =>
                `<a href="${item.href}" class="${item.href === here ? "active" : ""}">` +
                `${navIcon(item.icon)}<span>${escapeHtml(item.label)}</span></a>`
            )
            .join("");
        const barRect = bar.getBoundingClientRect();
        const anchorRect = anchorEl.getBoundingClientRect();
        flyoutEl.style.left = `${barRect.right + 6}px`;
        flyoutEl.style.top = `${anchorRect.top}px`;
        // Зажимаем по нижнему краю экрана уже после того, как контент
        // отрисован и известна реальная высота карточки.
        requestAnimationFrame(() => {
          const maxTop = window.innerHeight - flyoutEl.offsetHeight - 8;
          flyoutEl.style.top = `${Math.min(anchorRect.top, Math.max(8, maxTop))}px`;
        });
      });
    };
    const hideFlyout = () => {
      flyout.cancelShow();
      flyout.scheduleHide();
    };

    const triggers = [titleBtn, ...group.querySelectorAll(".nav-group-items a")];
    triggers.forEach((el) => {
      el.addEventListener("mouseenter", () => showFlyout(el));
      el.addEventListener("mouseleave", hideFlyout);
    });
  });
}

function initTopbar() {
  const nav = document.getElementById("nav");
  if (nav) {
    const here = location.pathname.split("/").pop() || "index.html";
    const activeGroup = NAV_GROUPS.find((g) => g.items.some((i) => i.href === here));
    const openGroups = loadOpenGroups(activeGroup ? activeGroup.title : null);

    nav.innerHTML = NAV_GROUPS.map((group) => {
      const isOpen = !group.title || openGroups.has(group.title);
      // Тултип на отдельной иконке — только у пунктов без группы (сейчас
      // это один Дашборд): у групповых пунктов в свёрнутой рельсе вместо
      // тултипа на каждой иконке — один флайаут на всю группу (см. ниже),
      // два всплывающих подсказчика поверх одной иконки были бы лишним.
      const itemsHtml = group.items
        .map(
          (item) =>
            `<a href="${item.href}" class="${item.href === here ? "active" : ""}"` +
            `${group.title ? "" : ` data-tooltip="${item.label}"`}>` +
            `${navIcon(item.icon)}<span class="nav-label">${item.label}</span></a>`
        )
        .join("");
      // Значок зоны (по запросу пользователя, 2026-09-24: "4 рабочие
      // зоны и внутри рабочие инструменты" — в свёрнутой рельсе группа
      // сжимается до одной кликабельной иконки-зоны вместо плоского
      // списка всех её пунктов, инструменты — через флайаут).
      const titleHtml = group.title
        ? `<button type="button" class="nav-group-title${isOpen ? " open" : ""}" data-group="${escapeHtml(group.title)}">` +
          navIcon(group.icon) +
          `<span>${group.title}</span>${navIcon("chevron", "nav-chevron")}</button>`
        : "";
      // Флайаут группы (по референсу пользователя, 2026-09-23: наведение
      // на группу в свёрнутой рельсе — всплывающая карточка со списком её
      // пунктов) — свои ссылки, не дублируют .nav a из рельсы визуально,
      // подписи видны всегда, не только при pinned.
      const flyoutHtml = group.title
        ? `<div class="nav-flyout">
             <div class="nav-flyout-title">${group.title}</div>
             ${group.items
               .map(
                 (item) =>
                   `<a href="${item.href}" class="${item.href === here ? "active" : ""}">` +
                   `${navIcon(item.icon)}<span>${item.label}</span></a>`
               )
               .join("")}
           </div>`
        : "";
      return (
        `<div class="nav-group">${titleHtml}` +
        `<div class="nav-group-items${isOpen ? "" : " collapsed"}">${itemsHtml}</div>${flyoutHtml}</div>`
      );
    }).join("");

    const allTitleButtons = nav.querySelectorAll(".nav-group-title[data-group]");
    allTitleButtons.forEach((btn) => {
      btn.addEventListener("click", () => {
        const items = btn.nextElementSibling;
        const nowOpen = items.classList.toggle("collapsed") === false;
        btn.classList.toggle("open", nowOpen);
        // Состояние берём из реально отрисованной панели (а не из
        // localStorage, где до первого клика ещё ничего не сохранено) —
        // иначе группа, открытая по умолчанию как "с текущей страницей",
        // терялась бы из сохранённого набора при первом же клике по
        // другой группе.
        const open = new Set();
        allTitleButtons.forEach((b) => {
          if (b.classList.contains("open")) open.add(b.dataset.group);
        });
        saveOpenGroups(open);
      });
    });

    setupFloatingPopups(nav);
  }
  setupNavToggle();
  setupSidebarPin();

  // Название режем на первую букву и хвост: в свёрнутой панели виден
  // только «G», при наведении дорисовывается остальное.
  const brandName = document.querySelector(".brand b");
  if (brandName && !brandName.querySelector(".brand-rest")) {
    const full = brandName.textContent;
    brandName.innerHTML =
      `<span class="brand-badge">${full.slice(0, 1)}</span>` +
      `<span class="brand-rest">${full.slice(1)}</span>`;
  }
  // Подпись "сеть · опрос · триггеры" под названием — убрана по запросу
  // пользователя (2026-09-24, сравнение с Zabbix: под логотипом там
  // ничего лишнего нет).
  const brandTagline = document.querySelector(".brand > span");
  if (brandTagline) brandTagline.remove();

  // Аватар со статусом — виден и в свёрнутой рельсе, не только в
  // закреплённой панели (п.6 сравнения с референсом, 2026-09-24).
  // Вставляется перед #role-pill, буква/точка заполняются в
  // updateRolePill() ниже.
  const rolePillEl = document.getElementById("role-pill");
  if (rolePillEl && !document.getElementById("user-avatar")) {
    const avatar = document.createElement("div");
    avatar.id = "user-avatar";
    avatar.className = "user-avatar";
    avatar.innerHTML = `<span class="user-avatar-letter">?</span><span class="user-avatar-dot"></span>`;
    rolePillEl.parentElement.insertBefore(avatar, rolePillEl);
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
