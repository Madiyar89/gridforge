// Вероятные хабы — живой опрос MAC-таблицы (+ CDP-уточнение) по группе или всему парку.

const VERDICT_LABELS = {
  hub: { text: "похоже на хаб", cls: "critical" },
  maybe_phone: { text: "возможно телефон+ПК", cls: "medium" },
  phone_confirmed: { text: "телефон (подтверждено CDP)", cls: "low" },
  switch_misclassified: { text: "это коммутатор — сделать порт trunk", cls: "medium" },
};

async function loadGroupPicker() {
  const select = document.getElementById("hubs-group-select");
  try {
    const groups = await api("/api/groups");
    select.innerHTML =
      `<option value="">весь парк</option>` +
      groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)} (${g.node_count} узел(ов))</option>`).join("");
  } catch (e) {
    /* тихо — весь парк как дефолт всё ещё работает без списка групп */
  }
}

async function runHubScan() {
  const body = document.getElementById("hubs-body");
  const btn = document.getElementById("hubs-scan");
  const groupId = document.getElementById("hubs-group-select").value;
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  body.innerHTML = `<div class="empty">Опрашиваю узлы — это может занять минуту…</div>`;
  try {
    const path = groupId ? `/api/reports/probable-hubs?group_id=${groupId}` : "/api/reports/probable-hubs";
    const data = await api(path, { method: "POST" });
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
      .map((r) => {
        const v = VERDICT_LABELS[r.verdict] || { text: r.verdict, cls: "medium" };
        return `<div class="domain-row" style="cursor:default">
      <div>
        <div class="name">${escapeHtml(r.hostname)} · ${escapeHtml(r.port)}</div>
        <div class="sub">${r.mac_count} MAC на порту</div>
      </div>
      <span class="risk-band ${v.cls}">${escapeHtml(v.text)}</span>
    </div>`;
      })
      .join("");
  }
  if (skipped.length > 0) {
    html += `<div class="hint">Пропущено: ${skipped.map(escapeHtml).join("; ")}</div>`;
  }
  body.innerHTML = html;
}

document.getElementById("hubs-scan").addEventListener("click", runHubScan);

function onKeySaved() {
  loadGroupPicker();
}

loadGroupPicker();
