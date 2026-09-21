// Схема портов коммутатора по последнему снимку.

let _protection = { ports: {}, summary: null };
let _lastPortsData = null;
let _nodesById = {};

const STATE_LABEL = {
  up: "линк есть",
  notconnect: "кабель не подключён",
  disabled: "выключен вручную",
  "err-disabled": "отключён защитой",
  unknown: "состояние не распознано",
};

async function refreshNodeList() {
  const select = document.getElementById("node-select");
  let nodes;
  try {
    nodes = sortNodesNatural(await api("/api/nodes"));
  } catch (e) {
    return;
  }
  _nodesById = Object.fromEntries(nodes.map((n) => [String(n.id), n]));
  const previous = select.value;
  select.innerHTML = nodes
    .map((n) => `<option value="${n.id}">${escapeHtml(n.name)} — ${escapeHtml(n.address)}</option>`)
    .join("");
  if (previous) select.value = previous;
  if (select.value) loadPorts();
}

document.getElementById("node-select").addEventListener("change", loadPorts);

async function loadPorts() {
  const nodeId = document.getElementById("node-select").value;
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
  document.getElementById("stp-body").hidden = true;
  document.getElementById("stp-toggle").textContent = "Открыть форму";
  document.getElementById("port-detail-body").innerHTML =
    `<span style="color:var(--text-dim)">Выбери порт на схеме</span>`;

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
        <div class="port-grid">
          ${group.ports
            .map((p) => {
              const num = p.name.split("/").pop();
              const prot = findProtection(p.name);
              const cls =
                `port ${p.state}` +
                (p.is_trunk ? " trunk" : "") +
                (prot && prot.leftover_settings ? " leftover" : "");
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
      body.querySelectorAll(".port.selected").forEach((s) => s.classList.remove("selected"));
      el.classList.add("selected");
      showPortDetail(byName[el.dataset.name]);
    });
  });
}

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
}

async function applyPortEdit(port, state) {
  const descInput = document.getElementById("edit-description");
  const vlanInput = document.getElementById("edit-vlan");
  const description = descInput.value.trim() !== (port.description || "") ? descInput.value.trim() : null;
  const vlan = vlanInput.value.trim() !== String(port.vlan || "") ? vlanInput.value.trim() : null;

  if (description === null && vlan === null && !state) {
    return toast("Нечего применять — ничего не изменилось", true);
  }

  const creds = askPortCredentials();
  if (!creds) return;

  const resultEl = document.getElementById("edit-result");
  const btn = document.getElementById("edit-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await api(
      `/api/nodes/${creds.nodeId}/ports/${encodeURIComponent(port.name)}/apply`,
      {
        method: "POST",
        body: JSON.stringify({ description, vlan, state, ...creds.auth }),
      }
    );
    renderApplyResult(resultEl, result);
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

  const creds = askPortCredentials();
  if (!creds) return;

  const resultEl = document.getElementById("ps-result");
  const btn = document.getElementById("ps-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await api(
      `/api/nodes/${creds.nodeId}/ports/${encodeURIComponent(port.name)}/apply`,
      {
        method: "POST",
        body: JSON.stringify({
          port_security: portSecurity,
          port_security_maximum: maximum,
          ...creds.auth,
        }),
      }
    );
    renderApplyResult(resultEl, result);
    if (result.ok) loadPorts();
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Применить Port Security";
  }
}

async function bouncePort(port) {
  if (!confirm(`Отбить порт ${port.name}: shutdown → пауза 5с → no shutdown. Продолжить?`)) return;

  const creds = askPortCredentials();
  if (!creds) return;

  const resultEl = document.getElementById("bounce-result");
  const btn = document.getElementById("bounce-apply");
  btn.disabled = true;
  btn.textContent = "Отбиваю…";
  try {
    const result = await api(
      `/api/nodes/${creds.nodeId}/ports/${encodeURIComponent(port.name)}/bounce`,
      { method: "POST", body: JSON.stringify(creds.auth) }
    );
    renderApplyResult(resultEl, result);
    if (result.ok) loadPorts();
  } catch (e) {
    resultEl.innerHTML = `<span style="color:var(--crit);">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Отбить порт";
  }
}

function askPortCredentials() {
  const nodeId = document.getElementById("node-select").value;
  const username = prompt("Логин для подключения к узлу:");
  if (!username) return null;
  const password = prompt("Пароль (пусто — если вход по ключу):") || null;
  return { nodeId, auth: { username, password } };
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

document.getElementById("refresh-ports").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) return toast("Выбери узел", true);

  // Учётка спрашивается каждый раз и никуда не сохраняется — тот же
  // принцип, что в Рубке и при снятии бэкапа.
  const username = prompt("Логин для подключения к узлу:");
  if (!username) return;
  const password = prompt("Пароль (пусто — если вход по ключу):") || null;

  const btn = document.getElementById("refresh-ports");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  try {
    const result = await api(`/api/nodes/${nodeId}/ports/refresh`, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (result.ok) {
      toast(`Снято портов: ${result.ports}`);
    } else {
      toast(result.error || "Не удалось снять состояние", true);
    }
    loadPorts();
  } catch (e) {
    toast(e.message, true);
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
  const nodeId = document.getElementById("node-select").value;
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

  const creds = askPortCredentials();
  if (!creds) return;

  const resultEl = document.getElementById("stp-result");
  const btn = document.getElementById("stp-apply");
  btn.disabled = true;
  btn.textContent = "Применяю…";
  try {
    const result = await api(`/api/nodes/${creds.nodeId}/stp-protection/apply`, {
      method: "POST",
      body: JSON.stringify({
        access_ports: accessPorts,
        trunk_ports: trunkPorts,
        set_root_bridge: setRootBridge,
        root_bridge_vlans: rootBridgeVlans,
        bpdu_guard: bpduGuard,
        loop_guard: loopGuard,
        ...creds.auth,
      }),
    });
    renderApplyResult(resultEl, result);
    if (result.ok) loadPorts();
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
