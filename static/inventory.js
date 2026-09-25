// Инвентарь — Группы, Узлы, Проверки, Условия, Действия.

// Список узлов и проверок обновляется раз в REFRESH_MS (пересобирает
// body.innerHTML целиком) — состояние "развёрнут/свёрнут" нужно
// пережить это пересоздание DOM, поэтому хранится отдельно от разметки
// (по умолчанию свёрнуты, запрос пользователя 2026-09-25: список из
// нескольких десятков узлов иначе не окинуть взглядом).
const expandedNodes = new Set();
// То же самое, но для заголовков групп ("Группа-Б · Интернет"/"Группа-А ·
// Интернет") — запрос пользователя, 2026-09-25: свернуть/развернуть
// нужно не только отдельный узел, но и сразу весь список под
// заголовком группы. По умолчанию группы развёрнуты (в отличие от
// узлов внутри них) — сворачивание узлов уже решает задачу компактности,
// группа целиком нужна реже.
const collapsedGroups = new Set();

// Вариант B/C плана дашборда по образцу Netdata (запрос пользователя,
// 2026-09-25: "делай всё по порядку") — график значений проверки с
// линией порога условия. Список watches по probe.id нужен только на
// клик "график" (fetch по /api/probes/{id}/samples делается тогда же,
// не заранее) — держим отдельно от DOM, не в data-атрибуте: значения
// условий — произвольный текст, экранирование внутри HTML-атрибута
// лишний риск ради данных, которые и так уже есть в JS-объекте.
let _probeWatchesById = {};

async function refreshGroups() {
  const body = document.getElementById("groups-body");
  const select = document.getElementById("new-node-group");
  const filterSelect = document.getElementById("nodes-group-filter");
  const vlanSelect = document.getElementById("new-vlan-group");
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("groups-count").textContent = groups.length;

  const prevSelected = select.value;
  select.innerHTML =
    `<option value="">без группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  select.value = prevSelected;

  const prevFilter = filterSelect.value;
  filterSelect.innerHTML =
    `<option value="">все группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("") +
    `<option value="__none__">без группы</option>`;
  filterSelect.value = prevFilter;

  const prevVlanGroup = vlanSelect.value;
  vlanSelect.innerHTML =
    `<option value="">без группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  vlanSelect.value = prevVlanGroup;

  if (groups.length === 0) {
    body.innerHTML = `<div class="empty">Групп нет — все узлы в общем списке</div>`;
    return;
  }
  body.innerHTML = groups
    .map(
      (g) => `
      <div class="group-row">
        <span>${escapeHtml(g.name)} <span class="count">· ${g.node_count} узел(ов)</span></span>
        <button data-id="${g.id}" class="del-group">удалить</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".del-group").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/groups/${btn.dataset.id}`, { method: "DELETE" });
        toast("Группа удалена");
        refreshGroups();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

// Переход с Дашборда по клику на инцидент (index.html передаёт
// ?node=<id>) — прокручиваем к узлу и подсвечиваем его. Срабатывает
// один раз за загрузку страницы, не на каждое авто-обновление раз в 5
// секунд: иначе подсветка мигала бы бесконечно, пока страница открыта.
let scrolledToLinkedNode = false;
function scrollToLinkedNode() {
  if (scrolledToLinkedNode) return;
  const nodeId = new URLSearchParams(location.search).get("node");
  if (!nodeId) return;
  const el = document.getElementById(`node-${nodeId}`);
  if (!el) return;
  scrolledToLinkedNode = true;
  expandedNodes.add(Number(nodeId));
  el.classList.add("highlight", "expanded");
  const groupBlock = el.closest(".group-block");
  if (groupBlock) {
    collapsedGroups.delete(groupBlock.dataset.group);
    groupBlock.classList.remove("collapsed");
  }
  el.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function refreshNodes() {
  const body = document.getElementById("nodes-body");
  const filterValue = document.getElementById("nodes-group-filter").value;
  let nodes;
  try {
    nodes = sortNodesNatural(await api("/api/nodes"));
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (filterValue === "__none__") {
    nodes = nodes.filter((n) => !n.group_id);
  } else if (filterValue) {
    nodes = nodes.filter((n) => String(n.group_id) === filterValue);
  }
  document.getElementById("nodes-count").textContent = nodes.length;

  if (nodes.length === 0) {
    body.innerHTML = `<div class="empty">Узлов пока нет — добавь ниже</div>`;
    return;
  }

  const withProbes = await Promise.all(
    nodes.map(async (n) => {
      let probes = [];
      try {
        probes = await api(`/api/nodes/${n.id}/probes`);
      } catch (e) {
        /* нет прав или сбой — покажем узел без проверок */
      }
      probes = await Promise.all(
        probes.map(async (p) => {
          let watches = [];
          try {
            watches = await api(`/api/probes/${p.id}/watches`);
          } catch (e) {
            /* нет прав — покажем проверку без условий */
          }
          return { ...p, watches };
        })
      );
      return { ...n, probes };
    })
  );

  const byGroup = new Map();
  for (const n of withProbes) {
    const key = n.group_name || "Без группы";
    if (!byGroup.has(key)) byGroup.set(key, []);
    byGroup.get(key).push(n);
  }
  const groupNames = [...byGroup.keys()].sort((a, b) => {
    if (a === "Без группы") return 1;
    if (b === "Без группы") return -1;
    return a.localeCompare(b);
  });

  // При выбранном фильтре группа и так одна — повторять её название
  // заголовком над списком не нужно, это просто шум.
  const showHeadings = !filterValue && groupNames.length > 1;
  body.innerHTML = groupNames
    .map((groupName) => {
      const rows = byGroup.get(groupName).map(renderNodeItem).join("");
      if (!showHeadings) return rows;
      const isCollapsed = collapsedGroups.has(groupName);
      return `
        <div class="group-block${isCollapsed ? " collapsed" : ""}" data-group="${escapeHtml(groupName)}">
          <div class="group-heading group-toggle">
            <svg class="node-chevron" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.5 5l5 5-5 5"/></svg>
            ${escapeHtml(groupName)}
          </div>
          <div class="group-rows">${rows}</div>
        </div>`;
    })
    .join("");

  scrollToLinkedNode();

  body.querySelectorAll(".group-toggle").forEach((el) => {
    el.addEventListener("click", () => {
      const block = el.closest(".group-block");
      const groupName = block.dataset.group;
      if (collapsedGroups.has(groupName)) collapsedGroups.delete(groupName);
      else collapsedGroups.add(groupName);
      block.classList.toggle("collapsed");
    });
  });
  body.querySelectorAll(".node-toggle").forEach((el) => {
    el.addEventListener("click", () => {
      const item = el.closest(".node-item");
      const nodeId = Number(item.id.slice("node-".length));
      if (expandedNodes.has(nodeId)) expandedNodes.delete(nodeId);
      else expandedNodes.add(nodeId);
      item.classList.toggle("expanded");
    });
  });
  body.querySelectorAll(".show-chart").forEach((btn) => {
    btn.addEventListener("click", () => toggleProbeChart(btn.dataset.probeId, btn));
  });
  body.querySelectorAll(".add-probe").forEach((btn) => {
    btn.addEventListener("click", () => openProbeModal(btn.dataset.nodeId, btn.dataset.nodeName));
  });
  body.querySelectorAll(".add-watch").forEach((btn) => {
    btn.addEventListener("click", () => openWatchModal(btn.dataset.probeId, btn.dataset.probeKind));
  });
  body.querySelectorAll(".add-action").forEach((btn) => {
    btn.addEventListener("click", () => openActionModal(btn.dataset.watchId, btn.dataset.watchLabel));
  });
  body.querySelectorAll(".del-node").forEach((btn) => {
    btn.addEventListener("click", () => deleteNode(btn.dataset.nodeId, btn.dataset.nodeName));
  });
  body.querySelectorAll(".del-probe").forEach((btn) => {
    btn.addEventListener("click", () => deleteProbe(btn.dataset.probeId, btn.dataset.probeKind));
  });
  body.querySelectorAll(".del-watch").forEach((btn) => {
    btn.addEventListener("click", () => deleteWatch(btn.dataset.watchId, btn.dataset.watchLabel));
  });
}

async function deleteNode(nodeId, nodeName) {
  if (!confirm(`Удалить узел «${nodeName}»?\n\nВместе с ним удалятся его проверки, история измерений, инциденты, бэкапы и результаты аудита. Syslog-сообщения останутся, но потеряют привязку к узлу.`)) return;
  try {
    const removed = await api(`/api/nodes/${nodeId}`, { method: "DELETE" });
    // Показываем, что именно ушло: удаление узла задевает многое, и
    // молчаливое "готово" тут выглядело бы подозрительно.
    toast(`Узел удалён: проверок ${removed.probes}, измерений ${removed.samples}, инцидентов ${removed.incidents}, бэкапов ${removed.backups}`);
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteProbe(probeId, kind) {
  if (!confirm(`Удалить проверку «${kind}» вместе с её историей и условиями?`)) return;
  try {
    await api(`/api/probes/${probeId}`, { method: "DELETE" });
    toast("Проверка удалена");
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
}

async function deleteWatch(watchId, label) {
  if (!confirm(`Удалить условие «${label}» вместе с его инцидентами и действиями?`)) return;
  try {
    await api(`/api/watches/${watchId}`, { method: "DELETE" });
    toast("Условие удалено");
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
}

// Вариант B/C плана дашборда по образцу Netdata (запрос пользователя,
// 2026-09-25) — график истории значений проверки прямо под её строкой
// в Инвентаре, с линией порога условия (gt/lt), если оно задано: видно
// не только "сработало/нет", а И ПОЧЕМУ — как значение шло к порогу.
async function toggleProbeChart(probeId, btn) {
  const box = document.getElementById(`chart-${probeId}`);
  const wasHidden = box.hidden;
  box.hidden = !wasHidden;
  btn.textContent = wasHidden ? "скрыть график" : "график";
  if (!wasHidden) return; // сворачиваем — запрос не нужен
  box.innerHTML = `<div class="empty" style="padding:8px 0;">Загрузка…</div>`;
  let samples;
  try {
    samples = await api(`/api/probes/${probeId}/samples?limit=50`);
  } catch (e) {
    box.innerHTML = `<div class="empty" style="padding:8px 0;">${emptyOrError(e)}</div>`;
    return;
  }
  renderProbeChart(box, samples, _probeWatchesById[probeId] || []);
}

function renderProbeChart(container, samples, watches) {
  // /api/probes/{id}/samples отдаёт по убыванию времени (свежее
  // первым) — для чтения слева направо графику нужен обратный порядок.
  const points = [...samples].reverse();
  const numeric = points.filter((p) => p.value !== null);
  if (numeric.length === 0) {
    container.innerHTML = `<div class="empty" style="padding:8px 0;">Нет числовых данных для графика (проверка не возвращает число)</div>`;
    return;
  }
  const thresholds = watches
    .filter((w) => (w.operator === "gt" || w.operator === "lt") && w.threshold !== null)
    .map((w) => ({ value: w.threshold, severity: w.severity, label: w.label }));

  const values = numeric.map((p) => p.value);
  const allValues = thresholds.length ? values.concat(thresholds.map((t) => t.value)) : values;
  const min = Math.min(...allValues);
  const max = Math.max(...allValues);
  const range = max - min || 1;
  const w = 600;
  const h = 90;
  const pad = 4;
  const stepX = numeric.length > 1 ? (w - pad * 2) / (numeric.length - 1) : 0;
  const yFor = (v) => h - pad - ((v - min) / range) * (h - pad * 2);
  const linePoints = numeric.map((p, i) => `${(pad + i * stepX).toFixed(1)},${yFor(p.value).toFixed(1)}`).join(" ");
  const dots = numeric
    .map((p, i) => {
      const cls = p.ok ? "" : "chart-dot-fail";
      return `<circle class="chart-dot ${cls}" cx="${(pad + i * stepX).toFixed(1)}" cy="${yFor(p.value).toFixed(1)}" r="2"><title>${escapeHtml(String(p.value))} · ${escapeHtml(timeAgo(p.taken_at))}</title></circle>`;
    })
    .join("");
  const thresholdLines = thresholds
    .map((t) => {
      const y = yFor(t.value).toFixed(1);
      return `<line class="chart-threshold sev-${t.severity}" x1="${pad}" y1="${y}" x2="${w - pad}" y2="${y}"><title>${escapeHtml(t.label)}: порог ${escapeHtml(String(t.value))}</title></line>`;
    })
    .join("");

  container.innerHTML = `
    <svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" class="probe-chart-svg">
      ${thresholdLines}
      <polyline points="${linePoints}" fill="none" class="chart-line"/>
      ${dots}
    </svg>
    <div class="probe-chart-range"><span>${escapeHtml(String(min))}</span><span>${escapeHtml(String(max))}</span></div>`;
}

function renderNodeItem(n) {
  const probeChips = n.probes.length
    ? n.probes
        .map((p) => {
          _probeWatchesById[p.id] = p.watches;
          const s = p.latest_sample;
          const dotClass = !s ? "unknown" : s.ok ? "up" : "down";
          let label = "нет данных";
          if (s) {
            if (s.ok) label = s.value !== null ? s.value : s.detail || "ok";
            else label = s.detail || (s.value !== null ? s.value : "ошибка");
          }
          const watchRows = p.watches
            .map(
              (w) => `
              <div class="probe-chip" style="margin-left:14px;background:var(--bg);">
                <span><span class="sev-dot ${w.severity}" style="display:inline-block"></span>${escapeHtml(w.label)}</span>
                <span class="chip-actions">
                  ${w.action_count > 0 ? `<span style="color:var(--text-dim)">${w.action_count} действ.</span>` : ""}
                  <button type="button" class="add-action" data-watch-id="${w.id}" data-watch-label="${escapeHtml(w.label)}">+ действие</button>
                  <button type="button" class="del-watch" data-watch-id="${w.id}" data-watch-label="${escapeHtml(w.label)}">×</button>
                </span>
              </div>`
            )
            .join("");
          return `<div class="probe-chip">
            <span><span class="ok-dot ${dotClass}"></span>${escapeHtml(p.kind)}</span>
            <span>${escapeHtml(String(label))}</span>
            <span class="chip-actions">
              <button type="button" class="show-chart" data-probe-id="${p.id}">график</button>
              <button type="button" class="add-watch" data-probe-id="${p.id}" data-probe-kind="${escapeHtml(p.kind)}">+ условие</button>
              <button type="button" class="del-probe" data-probe-id="${p.id}" data-probe-kind="${escapeHtml(p.kind)}">×</button>
            </span>
          </div>
          <div class="probe-chart" id="chart-${p.id}" hidden></div>
          ${watchRows}`;
        })
        .join("")
    : `<div class="probe-chip" style="color:var(--text-dim)">проверок нет</div>`;
  const vendorBadge = n.vendor ? `<span class="vendor-badge">${escapeHtml(n.vendor)}</span>` : "";
  const isExpanded = expandedNodes.has(n.id);
  return `
    <div class="node-item${isExpanded ? " expanded" : ""}" id="node-${n.id}">
      <div class="node-head">
        <span class="name node-toggle">
          <svg class="node-chevron" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7.5 5l5 5-5 5"/></svg>
          ${escapeHtml(n.name)}${vendorBadge}
        </span>
        <span class="actions">
          <span class="addr">${escapeHtml(n.address)}</span>
          <button type="button" class="icon-btn add-probe" data-node-id="${n.id}" data-node-name="${escapeHtml(n.name)}">+ проверка</button>
          <button type="button" class="icon-btn del-node" data-node-id="${n.id}" data-node-name="${escapeHtml(n.name)}">удалить узел</button>
        </span>
      </div>
      <div class="probe-list">${probeChips}</div>
    </div>`;
}

// --- Модалка "Новая проверка" ---

const probeModal = document.getElementById("probe-modal");
const probeForm = document.getElementById("probe-form");
let probeModalNodeId = null;

function openProbeModal(nodeId, nodeName) {
  probeModalNodeId = nodeId;
  document.getElementById("probe-modal-node").textContent = nodeName;
  probeForm.reset();
  onProbeKindChange();
  probeModal.showModal();
}

// Все SNMP-проверки делят один блок полей доступа (версия, community/USM,
// порт, OID) — различаются только свёрткой у walk и разрядностью у rate.
const SNMP_KINDS = ["snmp_get", "snmp_walk", "snmp_counter_rate"];

function onProbeKindChange() {
  const kind = document.getElementById("probe-kind").value;
  const paramsBlock = SNMP_KINDS.includes(kind) ? "snmp_get" : kind;
  document.querySelectorAll(".probe-params").forEach((el) => {
    el.hidden = el.id !== `probe-params-${paramsBlock}`;
  });
  document.getElementById("snmp-walk-fields").hidden = kind !== "snmp_walk";
  document.getElementById("snmp-rate-fields").hidden = kind !== "snmp_counter_rate";
  onSnmpVersionChange();
}
document.getElementById("probe-kind").addEventListener("change", onProbeKindChange);

function onSnmpVersionChange() {
  const isV3 = document.getElementById("p-snmp-version").value === "3";
  document.getElementById("snmp-v2-fields").hidden = isV3;
  document.getElementById("snmp-v3-fields").hidden = !isV3;
}
document.getElementById("p-snmp-version").addEventListener("change", onSnmpVersionChange);
document.getElementById("probe-cancel").addEventListener("click", () => probeModal.close());

function buildProbeParams(kind) {
  if (kind === "tcp_port") {
    const port = Number(document.getElementById("p-tcp-port").value);
    return port ? { port } : {};
  }
  if (kind === "ssh_command") {
    return {
      port: Number(document.getElementById("p-ssh-port").value) || 22,
      username: document.getElementById("p-ssh-user").value.trim(),
      key_path: document.getElementById("p-ssh-key").value.trim(),
      command: document.getElementById("p-ssh-cmd").value.trim(),
      expect_numeric: document.getElementById("p-ssh-numeric").checked,
    };
  }
  if (SNMP_KINDS.includes(kind)) {
    const version = document.getElementById("p-snmp-version").value;
    const oid = document.getElementById("p-snmp-oid").value.trim();
    const port = Number(document.getElementById("p-snmp-port").value) || 161;
    let params;
    if (version === "3") {
      params = {
        version,
        oid,
        port,
        username: document.getElementById("p-snmp-user").value.trim(),
        auth_protocol: document.getElementById("p-snmp-auth-proto").value,
        auth_password: document.getElementById("p-snmp-auth-pass").value || undefined,
        priv_protocol: document.getElementById("p-snmp-priv-proto").value,
        priv_password: document.getElementById("p-snmp-priv-pass").value || undefined,
      };
    } else {
      params = {
        community: document.getElementById("p-snmp-community").value.trim() || "public",
        version,
        oid,
        port,
      };
    }
    if (kind === "snmp_walk") {
      params.aggregate = document.getElementById("p-snmp-aggregate").value;
      params.max_rows = Number(document.getElementById("p-snmp-maxrows").value) || 500;
    }
    if (kind === "snmp_counter_rate") {
      params.counter_bits = Number(document.getElementById("p-snmp-bits").value) || 32;
      const maxRate = Number(document.getElementById("p-snmp-maxrate").value);
      if (maxRate > 0) params.max_rate = maxRate;
    }
    return params;
  }
  return {};
}

probeForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const kind = document.getElementById("probe-kind").value;
  const payload = {
    node_id: Number(probeModalNodeId),
    kind,
    interval_seconds: Number(document.getElementById("probe-interval").value) || 60,
    timeout_seconds: Number(document.getElementById("probe-timeout").value) || 2,
    params: buildProbeParams(kind),
  };
  try {
    await api("/api/probes", { method: "POST", body: JSON.stringify(payload) });
    probeModal.close();
    toast("Проверка добавлена");
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
});

// --- Модалка "Новое условие" (Watch) ---

const watchModal = document.getElementById("watch-modal");
const watchForm = document.getElementById("watch-form");
let watchModalProbeId = null;

function openWatchModal(probeId, probeKind) {
  watchModalProbeId = probeId;
  document.getElementById("watch-modal-probe").textContent = probeKind;
  watchForm.reset();
  onWatchOperatorChange();
  watchModal.showModal();
}

function onWatchOperatorChange() {
  const op = document.getElementById("w-operator").value;
  document.getElementById("w-threshold-row").hidden = op === "probe_failed";
}
document.getElementById("w-operator").addEventListener("change", onWatchOperatorChange);
document.getElementById("watch-cancel").addEventListener("click", () => watchModal.close());

watchForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const label = document.getElementById("w-label").value.trim();
  if (!label) return toast("Укажи название условия", true);
  const operator = document.getElementById("w-operator").value;
  const thresholdRaw = document.getElementById("w-threshold").value;
  const payload = {
    probe_id: Number(watchModalProbeId),
    operator,
    threshold: operator === "probe_failed" || thresholdRaw === "" ? null : Number(thresholdRaw),
    streak_required: Number(document.getElementById("w-streak").value) || 1,
    severity: document.getElementById("w-severity").value,
    label,
  };
  try {
    await api("/api/watches", { method: "POST", body: JSON.stringify(payload) });
    watchModal.close();
    toast("Условие добавлено");
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
});

// --- Модалка "Новое действие" (Action) — SSH-команда по срабатыванию
// конкретного Watch, кнопка "+ действие" рендерится под каждым условием
// в renderNodeItem() (см. GET /api/probes/{id}/watches).

const actionModal = document.getElementById("action-modal");
const actionForm = document.getElementById("action-form");
let actionModalWatchId = null;

function credentialOptionLabel(c) {
  const scope = c.node_name
    ? c.node_name
    : c.group_name
    ? `группа ${c.group_name}`
    : c.vendor
    ? `вендор ${c.vendor}`
    : "по умолчанию";
  return `${c.label || c.username} (${c.username}) — ${scope}`;
}

async function loadActionCredentials() {
  const select = document.getElementById("a-cred");
  const manualOption = select.querySelector('option[value="manual"]');
  let creds = [];
  try {
    creds = await api("/api/credentials");
  } catch (e) {
    return; // нет прав/сбой — оставим только "автоматически"/"вручную"
  }
  creds.forEach((c) => {
    const opt = document.createElement("option");
    opt.value = String(c.id);
    opt.textContent = credentialOptionLabel(c);
    select.insertBefore(opt, manualOption);
  });
}

function openActionModal(watchId, watchLabel) {
  actionModalWatchId = watchId;
  document.getElementById("action-modal-watch").textContent = watchLabel;
  actionForm.reset();
  document.getElementById("a-port").value = 22;
  document.getElementById("a-manual-fields").hidden = true;
  // Список учёток мог измениться с прошлого открытия (добавили/удалили) —
  // перезагружаем каждый раз, а не один раз при загрузке страницы.
  const select = document.getElementById("a-cred");
  select.querySelectorAll("option:not([value=''],[value='manual'])").forEach((o) => o.remove());
  loadActionCredentials();
  actionModal.showModal();
}

document.getElementById("a-cred").addEventListener("change", (e) => {
  document.getElementById("a-manual-fields").hidden = e.target.value !== "manual";
});

document.getElementById("action-cancel").addEventListener("click", () => actionModal.close());

actionForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const credValue = document.getElementById("a-cred").value;
  const config = {
    port: Number(document.getElementById("a-port").value) || 22,
    command: document.getElementById("a-cmd").value.trim(),
  };
  if (credValue === "manual") {
    config.username = document.getElementById("a-user").value.trim();
    config.key_path = document.getElementById("a-key").value.trim();
  } else if (credValue) {
    config.credential_id = Number(credValue);
  }
  // credValue === "" ("Автоматически") — ни username, ни credential_id
  // не передаём, сервер сам резолвит учётку по узлу (см. actions_engine.py).
  const payload = { watch_id: Number(actionModalWatchId), kind: "ssh_command", config };
  try {
    await api("/api/actions", { method: "POST", body: JSON.stringify(payload) });
    actionModal.close();
    toast("Действие добавлено");
  } catch (e) {
    toast(e.message, true);
  }
});

document.getElementById("add-group").addEventListener("click", async () => {
  const name = document.getElementById("new-group-name").value.trim();
  if (!name) return toast("Укажи имя группы", true);
  try {
    await api("/api/groups", { method: "POST", body: JSON.stringify({ name }) });
    document.getElementById("new-group-name").value = "";
    toast("Группа добавлена");
    refreshGroups();
  } catch (e) {
    toast(e.message, true);
  }
});

document.getElementById("add-node").addEventListener("click", async () => {
  const name = document.getElementById("new-node-name").value.trim();
  const address = document.getElementById("new-node-addr").value.trim();
  const groupId = document.getElementById("new-node-group").value;
  const vendor = document.getElementById("new-node-vendor").value;
  if (!name || !address) return toast("Укажи имя и адрес", true);
  try {
    await api("/api/nodes", {
      method: "POST",
      body: JSON.stringify({
        name,
        address,
        group_id: groupId ? Number(groupId) : null,
        vendor: vendor || null,
      }),
    });
    document.getElementById("new-node-name").value = "";
    document.getElementById("new-node-addr").value = "";
    toast("Узел добавлен");
    refreshNodes();
  } catch (e) {
    toast(e.message, true);
  }
});

// Подсказки движка правил жизненного цикла устройств (docs/
// landscape-report.md, §4.6) — сам эндпоинт только читает, применение
// подсказки — обычные POST /api/groups / PATCH /api/nodes, те же вызовы,
// что делает остальной инвентарь руками.

async function refreshLifecycle() {
  const panel = document.getElementById("lifecycle-panel");
  const body = document.getElementById("lifecycle-body");
  let data;
  try {
    data = await api("/api/lifecycle/suggestions");
  } catch (e) {
    panel.style.display = "none";
    return;
  }
  const rows = [];

  data.vendor_grouping.forEach((s, idx) => {
    rows.push(`
      <div class="channel-row" data-vendor-idx="${idx}">
        <span>${s.node_count} узл(ов) вендора <b>${escapeHtml(s.vendor)}</b> без группы → ${s.existing_group_id ? `добавить в группу «${escapeHtml(s.suggested_group_name)}»` : `создать группу «${escapeHtml(s.suggested_group_name)}»`}</span>
        <button type="button" class="apply-vendor-grouping" data-idx="${idx}">Применить</button>
      </div>`);
  });

  data.offline_archival.forEach((s) => {
    const lastOk = s.last_ok_at ? new Date(s.last_ok_at).toLocaleDateString("ru-RU") : "никогда";
    rows.push(`
      <div class="channel-row">
        <span>Узел <b>${escapeHtml(s.name)}</b> (${escapeHtml(s.address)}) не отвечает ≥${s.offline_days} дней (последний успешный опрос: ${lastOk}) → заархивировать?</span>
        <button type="button" class="apply-offline-archive" data-node-id="${s.node_id}">Архивировать</button>
      </div>`);
  });

  if (rows.length === 0) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "";
  body.innerHTML = rows.join("");

  body.querySelectorAll(".apply-vendor-grouping").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const s = data.vendor_grouping[Number(btn.dataset.idx)];
      try {
        let groupId = s.existing_group_id;
        if (!groupId) {
          const created = await api("/api/groups", { method: "POST", body: JSON.stringify({ name: s.suggested_group_name }) });
          groupId = created.id;
        }
        await Promise.all(s.node_ids.map((nodeId) => api(`/api/nodes/${nodeId}`, { method: "PATCH", body: JSON.stringify({ group_id: groupId }) })));
        toast(`Применено: ${s.node_ids.length} узл(ов) → «${s.suggested_group_name}»`);
        refreshAll();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });

  body.querySelectorAll(".apply-offline-archive").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const nodeId = btn.dataset.nodeId;
      try {
        await api(`/api/nodes/${nodeId}`, { method: "PATCH", body: JSON.stringify({ active: false }) });
        toast("Узел заархивирован");
        refreshAll();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

// VLAN / сети (запрос пользователя, 2026-09-25): рядом с узлами-
// коммутаторами — сам сегмент сети как отдельная сущность. Проверка
// (кнопка "проверить") гоняет и пинг шлюза, и скан живых адресов разом
// (POST /api/vlans/{id}/check), синхронно — на подсеть/24 это секунды,
// отдельный polling-статус, как у долгих сканов, не нужен.

function vlanGatewayBadge(v) {
  if (!v.gateway) return `<span class="ok-dot unknown"></span>нет шлюза`;
  if (v.gateway_ok === null) return `<span class="ok-dot unknown"></span>${escapeHtml(v.gateway)} — не проверялся`;
  const cls = v.gateway_ok ? "up" : "down";
  const label = v.gateway_ok ? "отвечает" : v.gateway_detail || "не отвечает";
  return `<span class="ok-dot ${cls}"></span>${escapeHtml(v.gateway)} — ${escapeHtml(label)}`;
}

function vlanUtilizationText(v) {
  if (v.host_count === null) return "ещё не сканировался";
  return `${v.host_count} из ${v.usable_addresses} адресов (${v.utilization_pct}%)`;
}

async function refreshVlans() {
  const body = document.getElementById("vlans-body");
  let vlans;
  try {
    vlans = await api("/api/vlans");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("vlans-count").textContent = vlans.length;

  if (vlans.length === 0) {
    body.innerHTML = `<div class="empty">VLAN/сетей пока нет — добавь ниже</div>`;
    return;
  }
  body.innerHTML = vlans
    .map(
      (v) => `
      <div class="node-item">
        <div class="node-head">
          <span class="name">${escapeHtml(v.name)}${v.vlan_id ? `<span class="vendor-badge">VLAN ${v.vlan_id}</span>` : ""}</span>
          <span class="actions">
            <span class="addr">${escapeHtml(v.cidr)}${v.group_name ? ` · ${escapeHtml(v.group_name)}` : ""}</span>
            <button type="button" class="icon-btn check-vlan" data-id="${v.id}">проверить</button>
            <button type="button" class="icon-btn del-vlan" data-id="${v.id}" data-name="${escapeHtml(v.name)}">удалить</button>
          </span>
        </div>
        <div class="probe-list">
          <div class="probe-chip"><span>${vlanGatewayBadge(v)}</span></div>
          <div class="probe-chip"><span>${escapeHtml(vlanUtilizationText(v))}</span></div>
        </div>
      </div>`
    )
    .join("");

  body.querySelectorAll(".check-vlan").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "проверяю…";
      try {
        await api(`/api/vlans/${btn.dataset.id}/check`, { method: "POST" });
        toast("Проверка выполнена");
        refreshVlans();
      } catch (e) {
        toast(e.message, true);
        btn.disabled = false;
        btn.textContent = "проверить";
      }
    });
  });
  body.querySelectorAll(".del-vlan").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить VLAN «${btn.dataset.name}»?`)) return;
      try {
        await api(`/api/vlans/${btn.dataset.id}`, { method: "DELETE" });
        toast("VLAN удалён");
        refreshVlans();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-vlan").addEventListener("click", async () => {
  const name = document.getElementById("new-vlan-name").value.trim();
  const vlanIdRaw = document.getElementById("new-vlan-id").value.trim();
  const cidr = document.getElementById("new-vlan-cidr").value.trim();
  const gateway = document.getElementById("new-vlan-gateway").value.trim();
  const groupId = document.getElementById("new-vlan-group").value;
  const description = document.getElementById("new-vlan-desc").value.trim();
  if (!name || !cidr) return toast("Укажи имя и подсеть", true);
  try {
    await api("/api/vlans", {
      method: "POST",
      body: JSON.stringify({
        name,
        vlan_id: vlanIdRaw ? Number(vlanIdRaw) : null,
        cidr,
        gateway: gateway || null,
        group_id: groupId ? Number(groupId) : null,
        description: description || null,
      }),
    });
    document.getElementById("new-vlan-name").value = "";
    document.getElementById("new-vlan-id").value = "";
    document.getElementById("new-vlan-cidr").value = "";
    document.getElementById("new-vlan-gateway").value = "";
    document.getElementById("new-vlan-desc").value = "";
    toast("VLAN добавлен");
    refreshVlans();
  } catch (e) {
    toast(e.message, true);
  }
});

async function refreshAll() {
  await Promise.all([refreshGroups(), refreshNodes(), updateRolePill(), refreshLifecycle(), refreshVlans()]);
}

function onKeySaved() {
  refreshAll();
}

document.getElementById("nodes-group-filter").addEventListener("change", refreshNodes);

refreshAll();
setInterval(refreshAll, REFRESH_MS);
