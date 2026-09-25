// Дашборд — сводка и открытые инциденты.
// Вся статистика приходит одним запросом /api/dashboard (см.
// app/dashboard_engine.py): страница обновляется каждые 5 секунд, и
// десяток отдельных вызовов на виджет тут был бы заметен.

const SEVERITY_RANK = { critical: 2, warning: 1, info: 0 };

// Раньше "Проблемные узлы" (просто счётчик по узлу) и "Открытые
// инциденты" (плоский список) были двумя отдельными панелями,
// показывающими по сути одно и то же. Реальная находка при сравнении с
// референсными дашбордами (Zabbix Problems, Grafana) — там это всегда
// один список, сгруппированный по источнику, с цветной полосой
// серьёзности вместо точки. Группируем инциденты по узлу на клиенте:
// /api/incidents уже отдаёт node_id на каждой записи, второго запроса
// не нужно.
function renderIncidentsGrouped(incidents) {
  const body = document.getElementById("incidents-body");
  document.getElementById("incidents-count").textContent = incidents.length;

  if (incidents.length === 0) {
    body.innerHTML = `<div class="empty">Открытых инцидентов нет</div>`;
    return;
  }

  const byNode = new Map();
  for (const i of incidents) {
    if (!byNode.has(i.node_id)) {
      byNode.set(i.node_id, { node_id: i.node_id, name: i.node_name, address: i.node_address, worst: "info", items: [] });
    }
    const entry = byNode.get(i.node_id);
    entry.items.push(i);
    if (SEVERITY_RANK[i.severity] > SEVERITY_RANK[entry.worst]) entry.worst = i.severity;
  }
  const groups = [...byNode.values()].sort(
    (a, b) => SEVERITY_RANK[b.worst] - SEVERITY_RANK[a.worst] || b.items.length - a.items.length
  );

  body.innerHTML = groups
    .map((g) => {
      const rows = g.items
        .map(
          (i) => `
          <div class="incident-sub">
            <div class="main">
              <div class="label">${escapeHtml(i.label)}</div>
              <div class="detail">${escapeHtml(i.detail)}</div>
            </div>
            <div class="time">${timeAgo(i.opened_at)}</div>
          </div>`
        )
        .join("");
      return `
        <a class="node-group sev-${g.worst}" href="inventory.html?node=${g.node_id}">
          <div class="node-group-head">
            <div class="main">
              <div class="label">${escapeHtml(g.name)}</div>
              <div class="detail">${escapeHtml(g.address)}</div>
            </div>
            <div class="time">${g.items.length} шт.</div>
          </div>
          ${rows}
        </a>`;
    })
    .join("");
}

function renderHealth(summary) {
  const b = summary.backups;
  const a = summary.audit;
  const s = summary.syslog;
  const rows = [
    ["Бэкапов снято", b.last_24h, b.failed_24h > 0 ? `${b.failed_24h} с ошибкой` : ""],
    ["Узлов без единого бэкапа", b.never_backed_up, b.never_backed_up > 0 ? "нечего сравнивать при сбое" : ""],
    ["Замечаний аудита", a.failed, a.nodes_with_findings > 0 ? `на ${a.nodes_with_findings} узл.` : ""],
    ["Syslog-сообщений", s.last_24h, s.errors_24h > 0 ? `${s.errors_24h} уровня error и хуже` : ""],
  ];
  document.getElementById("health-body").innerHTML = rows
    .map(
      ([label, value, note]) => `
      <div class="incident-row">
        <div class="main">
          <div class="label">${escapeHtml(label)}</div>
          ${note ? `<div class="detail">${escapeHtml(note)}</div>` : ""}
        </div>
        <div class="time">${value}</div>
      </div>`
    )
    .join("");
}

async function refreshSummary() {
  let summary;
  try {
    summary = await api("/api/dashboard");
  } catch (e) {
    document.getElementById("health-body").innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("stat-crit").textContent = summary.incidents.critical;
  document.getElementById("stat-warn").textContent = summary.incidents.warning;
  document.getElementById("stat-info").textContent = summary.incidents.info;
  document.getElementById("stat-crit").closest(".stat").classList.toggle("active", summary.incidents.critical > 0);
  document.getElementById("stat-warn").closest(".stat").classList.toggle("active", summary.incidents.warning > 0);
  document.getElementById("stat-nodes").textContent = summary.nodes.total;
  document.getElementById("stat-silent").textContent = summary.nodes.silent;
  // Молчащие узлы подсвечиваем, только когда они есть: постоянно красный
  // счётчик с нулём перестаёт читаться как сигнал.
  document.getElementById("stat-silent-box").className = summary.nodes.silent > 0 ? "stat warn" : "stat";

  renderHealth(summary);
}

async function refreshIncidents() {
  const body = document.getElementById("incidents-body");
  let incidents;
  try {
    incidents = await api("/api/incidents");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  renderIncidentsGrouped(incidents);
}

// Стена узлов (вариант D плана по образцу Netdata Overview, запрос
// пользователя 2026-09-25) — плотная сетка ВСЕХ видимых узлов цветными
// плитками, в отличие от "Открытых инцидентов" ниже (только те, где
// что-то не так) тут видно и то, что молчит, и то, что просто ок —
// одним взглядом на весь парк, без прокрутки длинного списка.
const WALL_STATUS_LABEL = { ok: "ок", critical: "critical", warning: "warning", silent: "молчит" };

async function refreshNodeWall() {
  const body = document.getElementById("node-wall");
  let nodes;
  try {
    nodes = await api("/api/dashboard/node-wall");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("wall-count").textContent = nodes.length;
  if (nodes.length === 0) {
    body.innerHTML = `<div class="empty">Узлов пока нет</div>`;
    return;
  }
  body.innerHTML = `<div class="node-wall-grid">${nodes
    .map(
      (n) => `
      <a class="wall-tile wall-${n.status}" href="inventory.html?node=${n.id}" title="${escapeHtml(n.name)} · ${escapeHtml(n.address)} · ${escapeHtml(WALL_STATUS_LABEL[n.status] || n.status)}${n.incident_count ? ` · ${n.incident_count} шт.` : ""}"></a>`
    )
    .join("")}</div>`;
}

// Спарклайн в карточках CRITICAL/WARNING (по образцу Netdata — живой
// мини-график прямо в самой метрике, запрос пользователя 2026-09-25).
// Свой интервал обновления, реже основного REFRESH_MS: часовой график
// не меняется настолько, чтобы дёргать его каждые 5 секунд.
const SPARK_REFRESH_MS = 60000;

function renderSparkline(svgId, values) {
  const svg = document.getElementById(svgId);
  if (!svg) return;
  const max = Math.max(1, ...values);
  const w = 100;
  const h = 28;
  const stepX = values.length > 1 ? w / (values.length - 1) : w;
  const points = values.map((v, i) => `${(i * stepX).toFixed(1)},${(h - (v / max) * (h - 2) - 1).toFixed(1)}`).join(" ");
  svg.innerHTML = `<polyline points="${points}" fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke"/>`;
}

async function refreshTrend() {
  let trend;
  try {
    trend = await api("/api/dashboard/incident-trend");
  } catch (e) {
    return;
  }
  renderSparkline("stat-crit-spark", trend.critical);
  renderSparkline("stat-warn-spark", trend.warning);
}

async function refreshAll() {
  await Promise.all([refreshSummary(), refreshIncidents(), refreshNodeWall(), updateRolePill()]);
}

function onKeySaved() {
  refreshAll();
  refreshTrend();
}

refreshAll();
refreshTrend();
setInterval(refreshAll, REFRESH_MS);
setInterval(refreshTrend, SPARK_REFRESH_MS);
