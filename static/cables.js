// Журнал учёта кабельных соединений — гибридная схема: один конец всегда
// реальный узел+порт GridForge, второй — свободный текст (розетка/патч-
// панель/ПК). Структура страницы по образцу vuln.js (группа → форма →
// список → скачать .xlsx).

let _clGroupId = null;
let _clAllNodes = [];
let _clEditingId = null;

async function refreshCableGroups() {
  const select = document.getElementById("cl-group-select");
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  const previous = select.value;
  select.innerHTML =
    `<option value="">выбери группу…</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  if (previous) select.value = previous;
}

document.getElementById("cl-group-select").addEventListener("change", onCableGroupChange);

async function onCableGroupChange() {
  _clGroupId = document.getElementById("cl-group-select").value || null;
  _clEditingId = null;
  const nodeSelect = document.getElementById("cl-node");
  const portSelect = document.getElementById("cl-port");
  if (!_clGroupId) {
    nodeSelect.innerHTML = `<option value="">выбери группу…</option>`;
    portSelect.innerHTML = `<option value="">сначала выбери узел…</option>`;
    document.getElementById("cl-table").innerHTML = `<tbody><tr><td class="empty">Выбери группу выше</td></tr></tbody>`;
    document.getElementById("cl-count").textContent = "";
    document.getElementById("cl-download").removeAttribute("data-href");
    document.getElementById("cl-schedules-body").innerHTML = `<div class="empty">Выбери группу выше</div>`;
    return;
  }
  if (_clAllNodes.length === 0) {
    try {
      _clAllNodes = await api("/api/nodes");
    } catch (e) {
      return;
    }
  }
  const nodes = _clAllNodes.filter((n) => String(n.group_id) === String(_clGroupId));
  nodeSelect.innerHTML =
    `<option value="">выбери узел…</option>` +
    nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
  portSelect.innerHTML = `<option value="">сначала выбери узел…</option>`;
  refreshCableLinks();
  refreshCableSchedules();
}

document.getElementById("cl-node").addEventListener("change", onCableNodeChange);

async function onCableNodeChange() {
  const nodeId = document.getElementById("cl-node").value;
  const portSelect = document.getElementById("cl-port");
  if (!nodeId) {
    portSelect.innerHTML = `<option value="">сначала выбери узел…</option>`;
    return;
  }
  portSelect.innerHTML = `<option value="">загрузка портов…</option>`;
  let data;
  try {
    data = await api(`/api/nodes/${nodeId}/ports`);
  } catch (e) {
    portSelect.innerHTML = `<option value="">не удалось загрузить порты</option>`;
    return;
  }
  const ports = (data.groups || []).flatMap((g) => g.ports);
  if (ports.length === 0) {
    portSelect.innerHTML = `<option value="">снимок портов ещё не снят — введи вручную ниже</option>`;
    return;
  }
  portSelect.innerHTML =
    `<option value="">выбери порт…</option>` +
    ports.map((p) => `<option value="${escapeHtml(p.name)}">${escapeHtml(p.name)}${p.description ? " — " + escapeHtml(p.description) : ""}</option>`).join("");
}

const CABLE_STATUS_LABELS = { active: "в работе", spare: "резерв", damaged: "повреждён" };

function resetCableForm() {
  _clEditingId = null;
  document.getElementById("cl-other").value = "";
  document.getElementById("cl-type").value = "";
  document.getElementById("cl-length").value = "";
  document.getElementById("cl-status").value = "active";
  document.getElementById("cl-laid").value = "";
  document.getElementById("cl-responsible").value = "";
  document.getElementById("cl-comment").value = "";
  document.getElementById("cl-add").textContent = "Добавить";
}

document.getElementById("cl-add").addEventListener("click", async () => {
  if (!_clGroupId) return toast("Выбери группу", true);
  const nodeId = document.getElementById("cl-node").value;
  if (!nodeId) return toast("Выбери узел", true);
  const portName = document.getElementById("cl-port").value.trim();
  if (!portName) return toast("Укажи порт узла", true);
  const otherLabel = document.getElementById("cl-other").value.trim();
  if (!otherLabel) return toast("Опиши второй конец соединения", true);

  const lengthRaw = document.getElementById("cl-length").value;
  const payload = {
    node_id: Number(nodeId),
    port_name: portName,
    other_label: otherLabel,
    cable_type: document.getElementById("cl-type").value.trim() || null,
    length_m: lengthRaw ? Number(lengthRaw) : null,
    status: document.getElementById("cl-status").value,
    laid_on: document.getElementById("cl-laid").value || null,
    responsible: document.getElementById("cl-responsible").value.trim() || null,
    comment: document.getElementById("cl-comment").value.trim() || null,
  };

  try {
    if (_clEditingId) {
      await api(`/api/cable-links/${_clEditingId}`, { method: "PATCH", body: JSON.stringify(payload) });
      toast("Запись обновлена");
    } else {
      await api(`/api/groups/${_clGroupId}/cable-links`, { method: "POST", body: JSON.stringify(payload) });
      toast("Запись добавлена");
    }
    resetCableForm();
    refreshCableLinks();
  } catch (e) {
    toast(e.message, true);
  }
});

async function refreshCableLinks() {
  const table = document.getElementById("cl-table");
  const downloadBtn = document.getElementById("cl-download");
  if (!_clGroupId) return;
  downloadBtn.setAttribute("data-href", `/api/groups/${_clGroupId}/cable-links.xlsx`);
  let links;
  try {
    links = await api(`/api/groups/${_clGroupId}/cable-links`);
  } catch (e) {
    table.innerHTML = `<tbody><tr><td class="empty">${emptyOrError(e)}</td></tr></tbody>`;
    return;
  }
  document.getElementById("cl-count").textContent = links.length;
  if (links.length === 0) {
    table.innerHTML = `<tbody><tr><td class="empty">Записей ещё нет</td></tr></tbody>`;
    return;
  }
  const headers = ["Узел", "Порт", "Второй конец", "Тип", "Длина, м", "Статус", "Источник", "Ответственный", "Дата", "Комментарий", ""];
  const thead = `<thead><tr>${headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>`;
  const tbody = links
    .map(
      (l) => `
      <tr>
        <td>${escapeHtml(l.node_name)}</td>
        <td style="font-family:var(--mono)">${escapeHtml(l.port_name)}</td>
        <td>${escapeHtml(l.other_label)}</td>
        <td>${escapeHtml(l.cable_type || "")}</td>
        <td>${l.length_m ?? ""}</td>
        <td><span class="status-badge ${l.status}">${escapeHtml(l.status_label)}</span></td>
        <td><span class="source-badge ${l.source}">${l.source === "cdp" ? "авто (CDP)" : "вручную"}</span></td>
        <td>${escapeHtml(l.responsible || "")}</td>
        <td>${escapeHtml(l.laid_on || "")}</td>
        <td>${escapeHtml(l.comment || "")}</td>
        <td class="row-actions">
          <button type="button" class="btn-ghost cl-edit" data-id="${l.id}">изменить</button>
          <button type="button" class="btn-ghost cl-delete" data-id="${l.id}">удалить</button>
        </td>
      </tr>`
    )
    .join("");
  table.innerHTML = thead + `<tbody>${tbody}</tbody>`;

  table.querySelectorAll(".cl-edit").forEach((btn) => {
    btn.addEventListener("click", () => startEditCableLink(links.find((l) => String(l.id) === btn.dataset.id)));
  });
  table.querySelectorAll(".cl-delete").forEach((btn) => {
    btn.addEventListener("click", () => deleteCableLink(btn.dataset.id));
  });
}

async function startEditCableLink(link) {
  if (!link) return;
  _clEditingId = link.id;
  document.getElementById("cl-node").value = link.node_id;
  await onCableNodeChange();
  document.getElementById("cl-port").value = link.port_name;
  document.getElementById("cl-other").value = link.other_label;
  document.getElementById("cl-type").value = link.cable_type || "";
  document.getElementById("cl-length").value = link.length_m ?? "";
  document.getElementById("cl-status").value = link.status;
  document.getElementById("cl-laid").value = link.laid_on || "";
  document.getElementById("cl-responsible").value = link.responsible || "";
  document.getElementById("cl-comment").value = link.comment || "";
  document.getElementById("cl-add").textContent = "Сохранить изменения";
  document.getElementById("cl-add").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function deleteCableLink(id) {
  if (!confirm("Удалить запись?")) return;
  try {
    await api(`/api/cable-links/${id}`, { method: "DELETE" });
    if (String(_clEditingId) === String(id)) resetCableForm();
    refreshCableLinks();
  } catch (e) {
    toast(e.message, true);
  }
}

document.getElementById("cl-download").addEventListener("click", (ev) => {
  const href = ev.currentTarget.getAttribute("data-href");
  if (!href) return toast("Выбери группу", true);
  window.location.href = href;
});

document.getElementById("cl-discover").addEventListener("click", async () => {
  if (!_clGroupId) return toast("Выбери группу", true);
  const btn = document.getElementById("cl-discover");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  try {
    const result = await api(`/api/groups/${_clGroupId}/cable-links/discover-trunks`, { method: "POST" });
    const parts = [`узлов проверено: ${result.checked_nodes}`, `новых: ${result.created}`, `обновлено: ${result.updated}`];
    if (result.skipped && result.skipped.length) parts.push(`пропущено: ${result.skipped.length}`);
    toast(parts.join(", "));
    refreshCableLinks();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Опросить транки сейчас";
  }
});

const CABLE_WEEKDAY_LABELS = ["понедельник", "вторник", "среда", "четверг", "пятница", "суббота", "воскресенье"];

async function refreshCableSchedules() {
  const body = document.getElementById("cl-schedules-body");
  if (!_clGroupId) return;
  let rows;
  try {
    rows = await api(`/api/groups/${_clGroupId}/cable-schedules`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (rows.length === 0) {
    body.innerHTML = `<div class="empty">Расписаний ещё нет — опрос только вручную</div>`;
    return;
  }
  body.innerHTML = rows
    .map((s) => {
      const last = s.last_triggered_on ? `, последний запуск: ${escapeHtml(s.last_triggered_on)}` : "";
      return `
        <div class="cable-sched-row${s.enabled ? "" : " disabled"}" data-id="${s.id}">
          <div>
            <div>${CABLE_WEEKDAY_LABELS[s.weekday]}, ${escapeHtml(s.start_time)}</div>
            <div class="meta">автоопрос транков (CDP)${last}</div>
          </div>
          <div class="actions">
            <button type="button" class="btn-ghost cs-toggle" data-id="${s.id}">${s.enabled ? "выключить" : "включить"}</button>
            <button type="button" class="btn-ghost cs-delete" data-id="${s.id}">удалить</button>
          </div>
        </div>`;
    })
    .join("");
  body.querySelectorAll(".cs-toggle").forEach((btn) => {
    btn.addEventListener("click", () => toggleCableSchedule(rows.find((r) => String(r.id) === btn.dataset.id)));
  });
  body.querySelectorAll(".cs-delete").forEach((btn) => {
    btn.addEventListener("click", () => deleteCableSchedule(btn.dataset.id));
  });
}

async function toggleCableSchedule(sched) {
  if (!sched) return;
  try {
    await api(`/api/cable-schedules/${sched.id}`, {
      method: "PATCH",
      body: JSON.stringify({ weekday: sched.weekday, start_time: sched.start_time, enabled: !sched.enabled }),
    });
    refreshCableSchedules();
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteCableSchedule(id) {
  if (!confirm("Удалить расписание?")) return;
  try {
    await api(`/api/cable-schedules/${id}`, { method: "DELETE" });
    refreshCableSchedules();
  } catch (e) {
    toast(e.message, true);
  }
}

document.getElementById("cs-add").addEventListener("click", async () => {
  if (!_clGroupId) return toast("Выбери группу", true);
  const weekday = Number(document.getElementById("cs-weekday").value);
  const start_time = document.getElementById("cs-start").value;
  if (!start_time) return toast("Укажи время", true);
  try {
    await api(`/api/groups/${_clGroupId}/cable-schedules`, {
      method: "POST",
      body: JSON.stringify({ weekday, start_time, enabled: true }),
    });
    toast("Расписание добавлено");
    refreshCableSchedules();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshCableGroups();
}

refreshCableGroups();
setInterval(() => {
  if (_clGroupId && !_clEditingId) refreshCableLinks();
}, REFRESH_MS);
