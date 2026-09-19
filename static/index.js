// Дашборд — открытые инциденты + сводная статистика.

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
  document.getElementById("stat-crit").textContent = incidents.filter((i) => i.severity === "critical").length;
  document.getElementById("stat-warn").textContent = incidents.filter((i) => i.severity === "warning").length;
  document.getElementById("stat-info").textContent = incidents.filter((i) => i.severity === "info").length;

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
          <div class="label">${escapeHtml(i.label)}</div>
          <div class="detail">${escapeHtml(i.detail)}</div>
        </div>
        <div class="time">${timeAgo(i.opened_at)}</div>
      </div>`
    )
    .join("");
}

async function refreshNodeCount() {
  try {
    const nodes = await api("/api/nodes");
    document.getElementById("stat-nodes").textContent = nodes.length;
  } catch (e) {
    /* без прав/ключа — просто не показываем число */
  }
}

async function refreshAll() {
  await Promise.all([refreshIncidents(), refreshNodeCount(), updateRolePill()]);
}

function onKeySaved() {
  refreshAll();
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
