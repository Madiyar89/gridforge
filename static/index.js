// Дашборд — сводка, проблемные узлы, открытые инциденты.
// Вся статистика приходит одним запросом /api/dashboard (см.
// app/dashboard_engine.py): страница обновляется каждые 5 секунд, и
// десяток отдельных вызовов на виджет тут был бы заметен.

function renderProblemNodes(nodes) {
  const body = document.getElementById("problem-body");
  document.getElementById("problem-count").textContent = nodes.length;
  if (nodes.length === 0) {
    body.innerHTML = `<div class="empty">Узлов с открытыми инцидентами нет</div>`;
    return;
  }
  body.innerHTML = nodes
    .map(
      (n) => `
      <div class="incident-row">
        <span class="sev-dot ${n.worst}"></span>
        <div class="main">
          <div class="label">${escapeHtml(n.name)}</div>
          <div class="detail">${escapeHtml(n.address)}</div>
        </div>
        <div class="time">${n.count} шт.</div>
      </div>`
    )
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
    document.getElementById("problem-body").innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    document.getElementById("health-body").innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("stat-crit").textContent = summary.incidents.critical;
  document.getElementById("stat-warn").textContent = summary.incidents.warning;
  document.getElementById("stat-info").textContent = summary.incidents.info;
  document.getElementById("stat-nodes").textContent = summary.nodes.total;
  document.getElementById("stat-silent").textContent = summary.nodes.silent;
  // Молчащие узлы подсвечиваем, только когда они есть: постоянно красный
  // счётчик с нулём перестаёт читаться как сигнал.
  document.getElementById("stat-silent-box").className = summary.nodes.silent > 0 ? "stat warn" : "stat";

  renderProblemNodes(summary.problem_nodes);
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
  document.getElementById("incidents-count").textContent = incidents.length;

  if (incidents.length === 0) {
    body.innerHTML = `<div class="empty">Открытых инцидентов нет</div>`;
    return;
  }
  body.innerHTML = incidents
    .map(
      (i) => `
      <div class="incident-row">
        <span class="sev-dot ${i.severity}"></span>
        <div class="main">
          <div class="label">${escapeHtml(i.node_name)} — ${escapeHtml(i.label)}</div>
          <div class="detail">${escapeHtml(i.detail)}</div>
        </div>
        <div class="time">${timeAgo(i.opened_at)}</div>
      </div>`
    )
    .join("");
}

async function refreshAll() {
  await Promise.all([refreshSummary(), refreshIncidents(), updateRolePill()]);
}

function onKeySaved() {
  refreshAll();
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
