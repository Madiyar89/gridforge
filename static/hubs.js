// Вероятные хабы — живой опрос MAC-таблицы по всем Cisco-узлам разом.

async function runHubScan() {
  const body = document.getElementById("hubs-body");
  const btn = document.getElementById("hubs-scan");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  body.innerHTML = `<div class="empty">Опрашиваю узлы — это может занять минуту…</div>`;
  try {
    const data = await api("/api/reports/probable-hubs", { method: "POST" });
    renderHubs(data);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Просканировать";
  }
}

function renderHubs(data) {
  const body = document.getElementById("hubs-body");
  const rows = data.rows || [];
  const skipped = data.skipped || [];
  let html = "";
  if (rows.length === 0) {
    html += `<div class="empty">Подозрительных портов не найдено</div>`;
  } else {
    html += rows
      .map(
        (r) => `<div class="domain-row" style="cursor:default">
      <div>
        <div class="name">${escapeHtml(r.hostname)} · ${escapeHtml(r.port)}</div>
        <div class="sub">${r.mac_count} MAC на порту</div>
      </div>
      <span class="risk-band ${r.verdict === "hub" ? "critical" : "medium"}">${r.verdict === "hub" ? "похоже на хаб" : "возможно телефон+ПК"}</span>
    </div>`
      )
      .join("");
  }
  if (skipped.length > 0) {
    html += `<div class="hint">Пропущено: ${skipped.map(escapeHtml).join("; ")}</div>`;
  }
  body.innerHTML = html;
}

document.getElementById("hubs-scan").addEventListener("click", runHubScan);
