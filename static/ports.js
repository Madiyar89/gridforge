// Схема портов коммутатора по последнему снимку.

let _protection = { ports: {}, summary: null };
let _lastPortsData = null;
let _nodesById = {};
let _allNodes = [];
let _selectedNodeId = null;
let _multiMode = false;
let _pickedPorts = new Set();

const STATE_LABEL = {
  up: "линк есть",
  notconnect: "кабель не подключён",
  disabled: "выключен вручную",
  "err-disabled": "отключён защитой",
  unknown: "состояние не распознано",
};

async function refreshNodeList() {
  let nodes, groups;
  try {
    [nodes, groups] = await Promise.all([api("/api/nodes"), api("/api/groups")]);
  } catch (e) {
    return;
  }
  nodes = sortNodesNatural(nodes);
  _allNodes = nodes;
  _nodesById = Object.fromEntries(nodes.map((n) => [String(n.id), n]));

  const groupSelect = document.getElementById("ports-group-select");
  const prevGroup = groupSelect.value;
  groupSelect.innerHTML =
    `<option value="">все группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("") +
    `<option value="__none__">без группы</option>`;
  groupSelect.value = prevGroup;

  renderNodeChips();
  if (!_selectedNodeId && _visibleNodes().length) {
    selectNode(_visibleNodes()[0].id);
  }
}

function _visibleNodes() {
  const filter = document.getElementById("ports-group-select").value;
  if (filter === "__none__") return _allNodes.filter((n) => !n.group_id);
  if (filter) return _allNodes.filter((n) => String(n.group_id) === filter);
  return _allNodes;
}

function renderNodeChips() {
  const list = document.getElementById("ports-node-list");
  const nodes = _visibleNodes();
  if (nodes.length === 0) {
    list.innerHTML = `<div class="empty">В этой группе узлов нет</div>`;
    return;
  }
  list.innerHTML = nodes
    .map(
      (n) => `
      <div class="node-chip${String(n.id) === String(_selectedNodeId) ? " active" : ""}" data-id="${n.id}">
        ${escapeHtml(n.name)}<span class="addr">${escapeHtml(n.address)}</span>
      </div>`
    )
    .join("");
  list.querySelectorAll(".node-chip").forEach((el) => {
    el.addEventListener("click", () => selectNode(el.dataset.id));
  });
}

function selectNode(nodeId) {
  _selectedNodeId = String(nodeId);
  _pickedPorts.clear();
  if (document.getElementById("bulk-port-status")) document.getElementById("bulk-port-status").textContent = "";
  if (document.getElementById("bulk-mac-report")) document.getElementById("bulk-mac-report").hidden = true;
  renderNodeChips();
  loadPorts();
}

document.getElementById("ports-group-select").addEventListener("change", () => {
  renderNodeChips();
  const visible = _visibleNodes();
  if (visible.length && !visible.some((n) => String(n.id) === String(_selectedNodeId))) {
    selectNode(visible[0].id);
  }
});

// resetUI=false — используется после apply/bounce/refresh НА ТОМ ЖЕ
// узле, когда пользователь только что смотрел результат в панели
// "Порт": по умолчанию loadPorts() стирает #port-detail-body и прячет
// форму STP (нужно при смене узла), и, вызванный сразу после успешного
// применения, вытирал бы собственное же сообщение об успехе раньше, чем
// его успевали прочитать — реальный баг, пойманный 2026-09-23 вместе с
// починкой "Port Security не обновляется на схеме".
async function loadPorts(resetUI = true) {
  const nodeId = _selectedNodeId;
  const body = document.getElementById("ports-body");
  if (!nodeId) return;

  let data, protection;
  try {
    // Защита приходит из последнего бэкапа, схема — из снимка портов:
    // это разные источники, и один может быть, когда другого нет.
    [data, protection] = await Promise.all([
      api(`/api/nodes/${nodeId}/ports`),
      api(`/api/nodes/${nodeId}/protection`).catch(() => ({ ports: {}, summary: null })),
    ]);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  _protection = protection;
  _lastPortsData = data;
  if (resetUI) {
    document.getElementById("stp-body").hidden = true;
    document.getElementById("stp-toggle").textContent = "Открыть форму";
    document.getElementById("port-detail-body").innerHTML =
      `<span style="color:var(--text-dim)">Выбери порт на схеме</span>`;
  }
  renderPortsGrid();
}

// Перерисовка сетки из уже загруженных _lastPortsData/_protection, без
// нового запроса к серверу — используется после точечного локального
// патча _protection (см. applyPortSecurity: реальный баг, 2026-09-23,
// "включил Port Security, а на схеме замок не появился" — protection
// приходит из последнего БЭКАПА, а не с устройства напрямую, apply
// новый бэкап не снимает, так что грузить с сервера после него незачем —
// перерисовываем тем, что только что реально применили).
function renderPortsGrid() {
  const body = document.getElementById("ports-body");
  const data = _lastPortsData;
  if (!data) return;

  const age = document.getElementById("snapshot-age");
  if (!data.taken_at) {
    age.textContent = "";
    body.innerHTML = `<div class="empty">Снимка ещё нет — нажми «Снять состояние»</div>`;
    document.getElementById("ports-summary").textContent = "";
    return;
  }

  // Возраст снимка показываем всегда: выключенный вчера порт иначе
  // выглядел бы как выключенный прямо сейчас.
  const ageText = `снято ${timeAgo(data.taken_at)}`;
  const stale = Date.now() - new Date(data.taken_at).getTime() > 24 * 3600 * 1000;
  age.innerHTML = stale ? `<span class="stale">${ageText}</span>` : ageText;

  if (!data.ok) {
    body.innerHTML = `<div class="empty">Последний снимок не удался: ${escapeHtml(data.error || "ошибка")}</div>`;
    return;
  }

  document.getElementById("ports-summary").textContent = Object.entries(data.summary)
    .map(([state, count]) => `${STATE_LABEL[state] || state}: ${count}`)
    .join(" · ");

  body.innerHTML =
    data.groups
      .map(
        (group) => `
        <div class="port-row-label">${
          group.ports.length === 1
            ? escapeHtml(group.ports[0].name)
            : `${escapeHtml(group.ports[0].name)} … ${escapeHtml(group.ports[group.ports.length - 1].name)} · ${group.ports.length} шт.`
        }</div>
        <div class="port-grid${_multiMode ? " multi-mode" : ""}">
          ${group.ports
            .map((p) => {
              const num = p.name.split("/").pop();
              const prot = findProtection(p.name);
              const cls =
                `port ${p.state}` +
                (p.is_trunk ? " trunk" : "") +
                (prot && prot.leftover_settings ? " leftover" : "") +
                (_multiMode && _pickedPorts.has(p.name) ? " multi-picked" : "");
              const lock = prot && prot.port_security ? '<span class="lock">🔒</span>' : "";
              return `<div class="${cls}" data-name="${escapeHtml(p.name)}" title="${escapeHtml(p.name)}">${escapeHtml(num)}${lock}</div>`;
            })
            .join("")}
        </div>`
      )
      .join("") +
    `
    <div class="port-legend">
      <span><i style="background:#1d3a28;border-color:#2f6b45"></i>линк есть</span>
      <span><i style="background:var(--surface-2)"></i>кабель не подключён</span>
      <span><i style="background:#3a1f1d;border-color:#6b2f2f"></i>выключен вручную</span>
      <span><i style="background:#4a1a16;border-color:#a33a2f"></i>отключён защитой</span>
      <span><i style="background:var(--surface-2);border-color:var(--info)"></i>уголок — trunk</span>
      <span>🔒 Port Security</span>
      <span><i style="background:var(--surface-2);border-color:var(--warn);border-style:dashed"></i>остались настройки защиты</span>
    </div>`;

  const byName = {};
  data.groups.forEach((g) => g.ports.forEach((p) => (byName[p.name] = p)));
  body.querySelectorAll(".port").forEach((el) => {
    el.addEventListener("click", () => {
      if (_multiMode) {
        toggleMultiPick(el.dataset.name, el);
        return;
      }
      body.querySelectorAll(".port.selected").forEach((s) => s.classList.remove("selected"));
      el.classList.add("selected");
      showPortDetail(byName[el.dataset.name]);
    });
  });
}

// --- Массовый выбор портов (вкл/выкл сразу нескольких) ---

function toggleMultiPick(name, el) {
  if (_pickedPorts.has(name)) {
    _pickedPorts.delete(name);
    el.classList.remove("multi-picked");
  } else {
    _pickedPorts.add(name);
    el.classList.add("multi-picked");
  }
  updateBulkPortBar();
}

function updateBulkPortBar() {
  document.getElementById("bulk-port-count").textContent = `Выбрано: ${_pickedPorts.size}`;
}

document.getElementById("multi-select-toggle").addEventListener("click", () => {
  _multiMode = !_multiMode;
  _pickedPorts.clear();
  document.getElementById("multi-select-toggle").textContent = _multiMode ? "Отменить выбор" : "Выбрать несколько";
  document.getElementById("bulk-port-bar").hidden = !_multiMode;
  document.getElementById("bulk-port-status").textContent = "";
  document.getElementById("bulk-mac-report").hidden = true;
  updateBulkPortBar();
  loadPorts();
});

document.getElementById("bulk-port-clear").addEventListener("click", () => {
  _pickedPorts.clear();
  document.getElementById("bulk-port-status").textContent = "";
  document.getElementById("bulk-mac-report").hidden = true;
  loadPorts();
});

async function bulkApplyPortState(state) {
  if (_pickedPorts.size === 0) return toast("Сначала выбери порты на схеме", true);
  const label = state === "up" ? "включить (no shutdown)" : "выключить (shutdown)";
  const names = [..._pickedPorts];
  if (!confirm(`${state === "up" ? "Включить" : "Выключить"} ${names.length} порт(ов): ${names.join(", ")}?`)) return;

  const nodeId = _selectedNodeId;
  const status = document.getElementById("bulk-port-status");
  const upBtn = document.getElementById("bulk-port-up");
  const downBtn = document.getElementById("bulk-port-down");
  upBtn.disabled = true;
  downBtn.disabled = true;
  let ok = 0;
  let failed = 0;
  for (let i = 0; i < names.length; i++) {
    status.textContent = `${i + 1}/${names.length} — ${names[i]}…`;
    try {
      const result = await apiWithCredentials(`/api/nodes/${nodeId}/ports/${encodeURIComponent(names[i])}/apply`, {
        method: "POST",
        body: JSON.stringify({ state }),
      });
      if (result.ok) ok++;
      else failed++;
    } catch (e) {
      failed++;
    }
  }
  upBtn.disabled = false;
  downBtn.disabled = false;
  status.textContent = `готово: успешно ${ok}, ошибок ${failed}`;
  toast(`Порты ${label}: успешно ${ok}, ошибок ${failed}`, failed > 0 && ok === 0);
  _pickedPorts.clear();
  // Состояние портов живёт в снимке, не в бэкапе — без живого опроса
  // схема осталась бы показывать старые цвета (тот же баг, что чинили в
  // applyPortEdit/bouncePort).
  refreshPortsLive(nodeId, { silent: true, resetUI: false });
}

document.getElementById("bulk-port-up").addEventListener("click", () => bulkApplyPortState("up"));
document.getElementById("bulk-port-down").addEventListener("click", () => bulkApplyPortState("down"));

// Отчёт по MAC-адресам на выбранных портах — перенос функции NetOpsHub
// (раздел Port Security: при массовом выборе портов показывал скан
// MAC — сколько устройств реально сидит на каком порту, до включения
// ограничения по количеству). Здесь: тот же живой запрос, что у кнопки
// "Показать MAC" в панели одного порта (/ports/{port}/mac), просто по
// очереди на все выбранные порты разом, с итоговой таблицей.
document.getElementById("bulk-port-mac").addEventListener("click", async () => {
  if (_pickedPorts.size === 0) return toast("Сначала выбери порты на схеме", true);
  const names = [..._pickedPorts];
  const nodeId = _selectedNodeId;
  const status = document.getElementById("bulk-port-status");
  const btn = document.getElementById("bulk-port-mac");
  const reportBox = document.getElementById("bulk-mac-report");
  const table = document.getElementById("bulk-mac-table");

  btn.disabled = true;
  const rows = [];
  for (let i = 0; i < names.length; i++) {
    status.textContent = `MAC ${i + 1}/${names.length} — ${names[i]}…`;
    try {
      const result = await apiWithCredentials(
        `/api/nodes/${nodeId}/ports/${encodeURIComponent(names[i])}/mac`,
        { method: "POST", body: JSON.stringify({}) }
      );
      rows.push({ name: names[i], ok: result.ok, macs: result.macs || [], error: result.error });
    } catch (e) {
      rows.push({ name: names[i], ok: false, macs: [], error: e.message });
    }
  }
  btn.disabled = false;
  status.textContent = `MAC: проверено портов ${names.length}`;

  const currentMax = (name) => {
    const prot = findProtection(name);
    return prot && prot.max_mac ? prot.max_mac : null;
  };

  table.innerHTML = `
    <thead><tr><th>Порт</th><th>MAC-адресов</th><th>Текущий максимум</th><th>Адреса</th></tr></thead>
    <tbody>
      ${rows
        .map((r) => {
          if (!r.ok) {
            return `<tr><td>${escapeHtml(r.name)}</td><td colspan="3" style="color:var(--crit)">${escapeHtml(r.error || "не удалось опросить")}</td></tr>`;
          }
          const max = currentMax(r.name);
          const over = max !== null && r.macs.length > max;
          const countCls = max === null ? "" : over ? "mac-count over" : "mac-count ok";
          return `
            <tr>
              <td>${escapeHtml(r.name)}</td>
              <td class="${countCls}">${r.macs.length}${over ? " — больше максимума!" : ""}</td>
              <td>${max === null ? "—" : max}</td>
              <td style="font-family:var(--mono);font-size:11px;">${r.macs.map((m) => escapeHtml(m.mac)).join(", ") || "—"}</td>
            </tr>`;
        })
        .join("")}
    </tbody>`;
  reportBox.hidden = false;
});

// В `show interfaces status` имена сокращённые (Gi1/0/1), а в
// конфигурации полные (GigabitEthernet1/0/1) — сопоставляем по числовой
// части и первой букве.
const IFACE_PREFIX = { Gi: "GigabitEthernet", Fa: "FastEthernet", Te: "TenGigabitEthernet", Eth: "Ethernet" };

function findProtection(shortName) {
  const ports = _protection.ports || {};
  if (ports[shortName]) return ports[shortName];
  const match = shortName.match(/^([A-Za-z]+)(.*)$/);
  if (!match) return null;
  const full = IFACE_PREFIX[match[1]];
  return full ? ports[full + match[2]] || null : null;
}

let _detailPort = null;

function showPortDetail(port) {
  if (!port) return;
  _detailPort = port;
  document.getElementById("port-detail-body").innerHTML = `
    <b>${escapeHtml(port.name)}</b>
    <dl>
      <dt>Состояние</dt><dd>${escapeHtml(STATE_LABEL[port.state] || port.state)}</dd>
      <dt>Описание</dt><dd>${escapeHtml(port.description || "—")}</dd>
      <dt>VLAN</dt><dd>${escapeHtml(port.vlan || "—")}${port.is_trunk ? " (trunk)" : ""}</dd>
      <dt>Скорость</dt><dd>${escapeHtml(port.speed || "—")}</dd>
      ${protectionRows(findProtection(port.name))}
    </dl>
    <div class="port-edit">
      <h3 style="margin:14px 0 6px;font-size:13px;">MAC-адреса на порту</h3>
      <button id="mac-fetch" class="btn-ghost">Показать MAC</button>
      <div id="mac-result" style="margin-top:8px;font-size:12px;"></div>

      <h3 style="margin:16px 0 6px;font-size:13px;">Флаппинг (Down/Up Time)</h3>
      <button id="downup-fetch" class="btn-ghost">Показать время up/down</button>
      <div id="downup-result" style="margin-top:8px;font-size:12px;"></div>

      <h3 style="margin:14px 0 6px;font-size:13px;">Изменить порт</h3>
      <div class="form-row">
        <input id="edit-description" placeholder="описание" value="${escapeHtml(port.description || "")}">
        <input id="edit-vlan" placeholder="VLAN" value="${escapeHtml(port.vlan || "")}" style="max-width:100px;">
      </div>
      <div class="form-row" style="gap:8px;margin-top:6px;">
        <button id="edit-up" class="btn-ghost">up</button>
        <button id="edit-down" class="btn-ghost">down</button>
        <span id="edit-state" style="color:var(--text-dim);font-size:12px;align-self:center;">
          состояние менять не будем
        </span>
      </div>
      <button id="edit-apply" style="margin-top:8px;">Применить</button>
      <div id="edit-result" style="margin-top:8px;font-size:12px;"></div>

      <h3 style="margin:16px 0 6px;font-size:13px;">Port Security</h3>
      <div class="form-row" style="gap:8px;">
        <button id="ps-on" class="btn-ghost">включить</button>
        <button id="ps-off" class="btn-ghost">выключить</button>
        <input id="ps-maximum" placeholder="максимум MAC (по умолчанию 2)" style="max-width:220px;">
      </div>
      <span id="ps-state" style="color:var(--text-dim);font-size:12px;">действие не выбрано</span>
      <button id="ps-apply" style="margin-top:8px;">Применить Port Security</button>
      <div id="ps-result" style="margin-top:8px;font-size:12px;"></div>

      <h3 style="margin:16px 0 6px;font-size:13px;">Отбить порт</h3>
      <p style="color:var(--text-dim);font-size:12px;margin:0 0 6px;">shutdown → пауза 5с → no shutdown.</p>
      <button id="bounce-apply" class="btn-ghost">Отбить порт</button>
      <div id="bounce-result" style="margin-top:8px;font-size:12px;"></div>
    </div>`;

  let pendingState = null;
  document.getElementById("edit-up").addEventListener("click", () => {
    pendingState = "up";
    document.getElementById("edit-state").textContent = "включить (no shutdown)";
  });
  document.getElementById("edit-down").addEventListener("click", () => {
    pendingState = "down";
    document.getElementById("edit-state").textContent = "выключить (shutdown)";
  });
  document.getElementById("edit-apply").addEventListener("click", () =>
    applyPortEdit(port, pendingState)
  );

  let pendingPortSecurity = null;
  document.getElementById("ps-on").addEventListener("click", () => {
    pendingPortSecurity = "on";
    document.getElementById("ps-state").textContent = "включить Port Security";
  });
  document.getElementById("ps-off").addEventListener("click", () => {
    pendingPortSecurity = "off";
    document.getElementById("ps-state").textContent = "выключить Port Security (и убрать настройки)";
  });
  document.getElementById("ps-apply").addEventListener("click", () =>
    applyPortSecurity(port, pendingPortSecurity)
  );

  document.getElementById("bounce-apply").addEventListener("click", () => bouncePort(port));
  document.getElementById("mac-fetch").addEventListener("click", () => fetchPortMac(port));
  document.getElementById("downup-fetch").addEventListener("click", () => fetchPortDownup(port));
}

async function fetchPortMac(port) {
  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("mac-result");
  const btn = document.getElementById("mac-fetch");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  resultEl.innerHTML = "";
  try {
    const result = await apiWithCredentials(
      `/api/nodes/${nodeId}/ports/${encodeURIComponent(port.name)}/mac`,
      { method: "POST", body: JSON.stringify({}) }
    );
    if (!result.ok) {
      resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(result.error || "не удалось опросить")}</span>`;
    } else if (result.macs.length === 0) {
      resultEl.innerHTML = `<span style="color:var(--text-dim);">MAC-адресов на порту не видно</span>`;
    } else {
      resultEl.innerHTML = result.macs
        .map((m) => `<div style="font-family:var(--mono);padding:2px 0;">${escapeHtml(m.mac)} · VLAN ${escapeHtml(m.vlan || "—")}${m.type ? " · " + escapeHtml(m.type) : ""}</div>`)
        .join("");
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Показать MAC";
  }
}

async function fetchPortDownup(port) {
  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("downup-result");
  const btn = document.getElementById("downup-fetch");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  resultEl.innerHTML = "";
  try {
    const result = await apiWithCredentials(
      `/api/nodes/${nodeId}/ports/${encodeURIComponent(port.name)}/downup`,
      { method: "POST", body: JSON.stringify({}) }
    );
    if (!result.ok) {
      resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(result.error || "не удалось опросить")}</span>`;
    } else {
      resultEl.innerHTML = `<div>Down Time: <b>${escapeHtml(result.down_time || "—")}</b></div><div>Up Time: <b>${escapeHtml(result.up_time || "—")}</b></div>`;
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Показать время up/down";
  }
}

async function applyPortEdit(port, state) {
  const descInput = document.getElementById("edit-description");
  const vlanInput = document.getElementById("edit-vlan");
  const description = descInput.value.trim() !== (port.description || "") ? descInput.value.trim() : null;
  const vlan = vlanInput.value.trim() !== String(port.vlan || "") ? vlanInput.value.trim() : null;

  if (description === null && vlan === null && !state) {
    return toast("Нечего применять — ничего не изменилось", true);
  }

  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("edit-result");
  const btn = document.getElementById("edit-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await apiWithCredentials(
      `/api/nodes/${nodeId}/ports/${encodeURIComponent(port.name)}/apply`,
      { method: "POST", body: JSON.stringify({ description, vlan, state }) }
    );
    renderApplyResult(resultEl, result);
    // Описание/VLAN/состояние живут в снимке портов (не в бэкапе) — без
    // нового живого опроса схема продолжала бы показывать старые
    // значения до следующего ручного "Снять состояние".
    if (result.ok) refreshPortsLive(nodeId, { silent: true, resetUI: false });
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Применить";
  }
}

async function applyPortSecurity(port, portSecurity) {
  const maximum = document.getElementById("ps-maximum").value.trim() || null;
  if (!portSecurity && !maximum) {
    return toast("Выбери включить/выключить или укажи максимум MAC", true);
  }

  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("ps-result");
  const btn = document.getElementById("ps-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await apiWithCredentials(
      `/api/nodes/${nodeId}/ports/${encodeURIComponent(port.name)}/apply`,
      {
        method: "POST",
        body: JSON.stringify({ port_security: portSecurity, port_security_maximum: maximum }),
      }
    );
    renderApplyResult(resultEl, result);
    if (result.ok) patchProtectionAfterApply(port.name, portSecurity, maximum);
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Применить Port Security";
  }
}

async function bouncePort(port) {
  if (!confirm(`Отбить порт ${port.name}: shutdown → пауза 5с → no shutdown. Продолжить?`)) return;

  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("bounce-result");
  const btn = document.getElementById("bounce-apply");
  btn.disabled = true;
  btn.textContent = "Отбиваю…";
  try {
    const result = await apiWithCredentials(
      `/api/nodes/${nodeId}/ports/${encodeURIComponent(port.name)}/bounce`,
      { method: "POST", body: JSON.stringify({}) }
    );
    renderApplyResult(resultEl, result);
    if (result.ok) refreshPortsLive(nodeId, { silent: true, resetUI: false });
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Отбить порт";
  }
}

// Тот же дефолт, что DEFAULT_PORT_SECURITY_MAXIMUM в app/port_commands.py
// — держать в согласии вручную, значение меняется крайне редко.
const DEFAULT_PORT_SECURITY_MAXIMUM = 2;

// Локальный патч _protection сразу после успешного apply — без нового
// запроса к серверу (protection читается из последнего БЭКАПА, а apply
// новый бэкап не снимает, поэтому loadPorts() после Port Security ничего
// не менял на схеме — реальный баг, 2026-09-23). Зеркалит ровно то, что
// apply_port реально применил на устройстве (см. build_config_lines в
// port_commands.py: "on" — port-security + maximum + violation restrict,
// "off" — полностью снимает все под-настройки).
function patchProtectionAfterApply(portName, portSecurity, maximum) {
  if (!_protection.ports) _protection.ports = {};
  const existing = findProtection(portName) || {};
  let entry;
  if (portSecurity === "on") {
    entry = {
      ...existing,
      port_security: true,
      max_mac: maximum ? Number(maximum) : DEFAULT_PORT_SECURITY_MAXIMUM,
      violation: "restrict",
      leftover_settings: false,
    };
  } else if (portSecurity === "off") {
    entry = { ...existing, port_security: false, max_mac: null, violation: null, sticky: false, leftover_settings: false };
  } else if (maximum) {
    entry = { ...existing, max_mac: Number(maximum) };
  } else {
    return;
  }
  _protection.ports[portName] = entry;
  renderPortsGrid();
}

function renderApplyResult(resultEl, result) {
  if (result.ok) {
    toast("Применено");
    resultEl.innerHTML = `<span style="color:var(--ok);">применено ✓</span> <code>${result.commands.map(escapeHtml).join(" · ")}</code>`;
  } else {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(result.error || "ошибка")}</span>`;
  }
}

function protectionRows(prot) {
  if (!prot) return `<dt>Защита</dt><dd>нет снимка конфигурации</dd>`;
  const bits = [];
  if (prot.port_security) {
    bits.push(
      `Port Security включён` +
        (prot.max_mac ? `, максимум MAC: ${prot.max_mac}` : "") +
        (prot.violation ? `, при нарушении: ${escapeHtml(prot.violation)}` : "") +
        (prot.sticky ? ", запоминание MAC (sticky)" : "")
    );
  } else if (prot.leftover_settings) {
    // Важное различие: настройки есть, а защиты нет.
    bits.push(`<span style="color:var(--warn)">Port Security выключен, но его настройки остались в конфигурации</span>`);
  } else {
    bits.push("Port Security выключен");
  }
  if (prot.bpdu_guard) bits.push("BPDU Guard");
  if (prot.bpdu_filter) bits.push(`<span style="color:var(--crit)">BPDU Filter — обработка BPDU отключена, петля не будет замечена</span>`);
  if (prot.portfast) bits.push("PortFast");
  if (prot.guard_root) bits.push("Guard Root");
  if (prot.guard_loop) bits.push("Guard Loop");
  return `<dt>Защита</dt><dd>${bits.join("<br>")}</dd>`;
}

document.getElementById("bulk-refresh").addEventListener("click", async () => {
  const nodes = _visibleNodes();
  if (nodes.length === 0) return toast("В этой группе узлов нет", true);
  if (!confirm(`Опросить порты на ${nodes.length} узле(ах)? Это может занять время — по одному, последовательно.`)) return;

  const btn = document.getElementById("bulk-refresh");
  const status = document.getElementById("bulk-refresh-status");
  btn.disabled = true;
  let ok = 0;
  let failed = 0;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    status.textContent = `${i + 1}/${nodes.length} — ${n.name}…`;
    try {
      const result = await apiWithCredentials(`/api/nodes/${n.id}/ports/refresh`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      if (result.ok) ok++;
      else failed++;
    } catch (e) {
      failed++;
    }
  }
  btn.disabled = false;
  status.textContent = `готово: успешно ${ok}, ошибок ${failed}`;
  toast(`Общий опрос завершён: успешно ${ok}, ошибок ${failed}`, failed > 0 && ok === 0);
  if (_selectedNodeId && nodes.some((n) => String(n.id) === String(_selectedNodeId))) loadPorts();
});

// Живой опрос устройства (то же самое, что кнопка "Снять состояние") —
// вынесено отдельно, чтобы применение правки порта/отбивка порта тоже
// могли дёрнуть реальный live-запрос, а не просто перерисовать старый
// кэш (реальный баг, 2026-09-23: после "Применить" на схеме ничего не
// менялось, потому что loadPorts() без /refresh читает тот же старый
// снимок из БД, а вовсе не спрашивает устройство заново).
async function refreshPortsLive(nodeId, { silent = false, resetUI = true } = {}) {
  try {
    const result = await apiWithCredentials(`/api/nodes/${nodeId}/ports/refresh`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    if (!silent) {
      if (result.ok) toast(`Снято портов: ${result.ports}`);
      else toast(result.error || "Не удалось снять состояние", true);
    }
  } catch (e) {
    if (!silent) toast(e.message, true);
  }
  await loadPorts(resetUI);
}

document.getElementById("refresh-ports").addEventListener("click", async () => {
  const nodeId = _selectedNodeId;
  if (!nodeId) return toast("Выбери узел", true);

  // Учётка берётся из центральной (Настройки → Учётки) — спрашиваем
  // вручную только если для узла не настроена ни своя, ни учётка по
  // умолчанию (см. apiWithCredentials в common.js).
  const btn = document.getElementById("refresh-ports");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  try {
    await refreshPortsLive(nodeId);
  } finally {
    btn.disabled = false;
    btn.textContent = "Снять состояние";
  }
});

document.getElementById("stp-toggle").addEventListener("click", () => {
  const body = document.getElementById("stp-body");
  const btn = document.getElementById("stp-toggle");
  body.hidden = !body.hidden;
  btn.textContent = body.hidden ? "Открыть форму" : "Скрыть форму";
  if (!body.hidden) renderStpForm();
});

function renderStpForm() {
  const body = document.getElementById("stp-body");
  if (!_lastPortsData || !_lastPortsData.groups) {
    body.innerHTML = `<div class="empty">Сначала сними состояние портов — список access/trunk берётся оттуда</div>`;
    return;
  }
  const nodeId = _selectedNodeId;
  const vendor = (_nodesById[nodeId] || {}).vendor;
  const isJunos = vendor === "junos";

  const allPorts = _lastPortsData.groups.flatMap((g) => g.ports);
  const accessDefault = allPorts.filter((p) => !p.is_trunk).map((p) => p.name);
  const trunkDefault = allPorts.filter((p) => p.is_trunk).map((p) => p.name);

  body.innerHTML = `
    <p style="color:var(--text-dim);font-size:12px;margin:0 0 10px;">
      Список access/trunk портов предзаполнен по последнему снимку — поправь при необходимости
      (через запятую). Root bridge выставляется только когда явно включён — не запускай на этажных
      access-свитчах, только на ядре/распределении.
    </p>
    <div class="form-row">
      <label style="display:flex;align-items:center;gap:6px;">
        <input type="checkbox" id="stp-root-bridge">
        Сделать этот коммутатор root bridge
      </label>
    </div>
    ${
      isJunos
        ? `<p style="color:var(--text-dim);font-size:11px;margin:4px 0 0;">Junos: один общий spanning-tree instance на всё устройство — список VLAN не нужен.</p>`
        : `<div class="form-row" style="margin-top:6px;">
             <input id="stp-vlans" placeholder="VLAN для root primary, через запятую (напр. 10, 527)">
           </div>`
    }
    <div class="form-row" style="margin-top:10px;">
      <label style="display:flex;align-items:center;gap:6px;">
        <input type="checkbox" id="stp-bpdu-guard" checked>
        BPDU Guard на access-портах
      </label>
    </div>
    <textarea id="stp-access-ports" rows="2" style="width:100%;margin-top:4px;">${accessDefault.join(", ")}</textarea>
    <div class="form-row" style="margin-top:10px;">
      <label style="display:flex;align-items:center;gap:6px;${isJunos ? "opacity:.5;" : ""}">
        <input type="checkbox" id="stp-loop-guard" ${isJunos ? "disabled" : "checked"}>
        Loop Guard на trunk-портах${isJunos ? " (не реализовано для Junos)" : ""}
      </label>
    </div>
    <textarea id="stp-trunk-ports" rows="2" style="width:100%;margin-top:4px;" ${isJunos ? "disabled" : ""}>${trunkDefault.join(", ")}</textarea>

    <button id="stp-apply" style="margin-top:12px;">Применить STP-защиту</button>
    <div id="stp-result" style="margin-top:8px;font-size:12px;"></div>`;

  document.getElementById("stp-apply").addEventListener("click", applyStpProtection);
}

function splitPortList(value) {
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

async function applyStpProtection() {
  const setRootBridge = document.getElementById("stp-root-bridge").checked;
  const vlansInput = document.getElementById("stp-vlans");
  const rootBridgeVlans = vlansInput ? splitPortList(vlansInput.value) : [];
  const bpduGuard = document.getElementById("stp-bpdu-guard").checked;
  const loopGuard = document.getElementById("stp-loop-guard").checked;
  const accessPorts = splitPortList(document.getElementById("stp-access-ports").value);
  const trunkPorts = splitPortList(document.getElementById("stp-trunk-ports").value);

  const nodeId = _selectedNodeId;
  const resultEl = document.getElementById("stp-result");
  const btn = document.getElementById("stp-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await apiWithCredentials(`/api/nodes/${nodeId}/stp-protection/apply`, {
      method: "POST",
      body: JSON.stringify({
        access_ports: accessPorts,
        trunk_ports: trunkPorts,
        set_root_bridge: setRootBridge,
        root_bridge_vlans: rootBridgeVlans,
        bpdu_guard: bpduGuard,
        loop_guard: loopGuard,
      }),
    });
    renderApplyResult(resultEl, result);
    if (result.ok) {
      // bpdu_guard/guard_loop живут в "Защите" (читается из последнего
      // БЭКАПА, не с устройства напрямую) и не рисуются на самой схеме —
      // применилось реально, но в панели порта будет видно только после
      // нового бэкапа. Честно говорим об этом, а не притворяемся, что
      // синхронизировалось само.
      // loadPorts() тут намеренно НЕ вызываем: он сбрасывает
      // stp-body.hidden=true (нужно только при смене узла) и сразу же
      // спрятал бы только что показанное сообщение об успехе — реальный
      // баг, пойманный вместе с этим же исправлением.
      resultEl.innerHTML += `<div style="margin-top:6px;color:var(--text-dim)">Применено на устройстве. В панели «Порт» (Защита) появится после нового бэкапа конфигурации — Бэкапы → Снять бэкап.</div>`;
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Применить STP-защиту";
  }
}

function onKeySaved() {
  refreshNodeList();
}

refreshNodeList();
