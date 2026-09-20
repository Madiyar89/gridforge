// Схема портов коммутатора по последнему снимку.

let _protection = { ports: {}, summary: null };

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
    nodes = await api("/api/nodes");
  } catch (e) {
    return;
  }
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
    </div>
    <div class="port-detail" id="port-detail"><span style="color:var(--text-dim)">Выбери порт на схеме</span></div>`;

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

function showPortDetail(port) {
  if (!port) return;
  document.getElementById("port-detail").innerHTML = `
    <b>${escapeHtml(port.name)}</b>
    <dl>
      <dt>Состояние</dt><dd>${escapeHtml(STATE_LABEL[port.state] || port.state)}</dd>
      <dt>Описание</dt><dd>${escapeHtml(port.description || "—")}</dd>
      <dt>VLAN</dt><dd>${escapeHtml(port.vlan || "—")}${port.is_trunk ? " (trunk)" : ""}</dd>
      <dt>Скорость</dt><dd>${escapeHtml(port.speed || "—")}</dd>
      ${protectionRows(findProtection(port.name))}
    </dl>`;
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

function onKeySaved() {
  refreshNodeList();
}

refreshNodeList();
