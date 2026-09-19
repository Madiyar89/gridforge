// Инвентарь — Группы, Узлы, Проверки, Условия, Действия.

async function refreshGroups() {
  const body = document.getElementById("groups-body");
  const select = document.getElementById("new-node-group");
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

async function refreshNodes() {
  const body = document.getElementById("nodes-body");
  let nodes;
  try {
    nodes = await api("/api/nodes");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
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

  body.innerHTML = groupNames
    .map((groupName) => {
      const rows = byGroup.get(groupName).map(renderNodeItem).join("");
      return `<div class="group-heading">${escapeHtml(groupName)}</div>${rows}`;
    })
    .join("");

  body.querySelectorAll(".add-probe").forEach((btn) => {
    btn.addEventListener("click", () => openProbeModal(btn.dataset.nodeId, btn.dataset.nodeName));
  });
  body.querySelectorAll(".add-watch").forEach((btn) => {
    btn.addEventListener("click", () => openWatchModal(btn.dataset.probeId, btn.dataset.probeKind));
  });
  body.querySelectorAll(".add-action").forEach((btn) => {
    btn.addEventListener("click", () => openActionModal(btn.dataset.watchId, btn.dataset.watchLabel));
  });
}

function renderNodeItem(n) {
  const probeChips = n.probes.length
    ? n.probes
        .map((p) => {
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
                </span>
              </div>`
            )
            .join("");
          return `<div class="probe-chip">
            <span><span class="ok-dot ${dotClass}"></span>${escapeHtml(p.kind)}</span>
            <span>${escapeHtml(String(label))}</span>
            <span class="chip-actions"><button type="button" class="add-watch" data-probe-id="${p.id}" data-probe-kind="${escapeHtml(p.kind)}">+ условие</button></span>
          </div>${watchRows}`;
        })
        .join("")
    : `<div class="probe-chip" style="color:var(--text-dim)">проверок нет</div>`;
  const vendorBadge = n.vendor ? `<span class="vendor-badge">${escapeHtml(n.vendor)}</span>` : "";
  return `
    <div class="node-item">
      <div class="node-head">
        <span class="name">${escapeHtml(n.name)}${vendorBadge}</span>
        <span class="actions">
          <span class="addr">${escapeHtml(n.address)}</span>
          <button type="button" class="icon-btn add-probe" data-node-id="${n.id}" data-node-name="${escapeHtml(n.name)}">+ проверка</button>
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

function onProbeKindChange() {
  const kind = document.getElementById("probe-kind").value;
  document.querySelectorAll(".probe-params").forEach((el) => {
    el.hidden = el.id !== `probe-params-${kind}`;
  });
}
document.getElementById("probe-kind").addEventListener("change", onProbeKindChange);
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
  if (kind === "snmp_get") {
    return {
      community: document.getElementById("p-snmp-community").value.trim() || "public",
      version: document.getElementById("p-snmp-version").value,
      oid: document.getElementById("p-snmp-oid").value.trim(),
    };
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

function openActionModal(watchId, watchLabel) {
  actionModalWatchId = watchId;
  document.getElementById("action-modal-watch").textContent = watchLabel;
  actionForm.reset();
  document.getElementById("a-port").value = 22;
  actionModal.showModal();
}

document.getElementById("action-cancel").addEventListener("click", () => actionModal.close());

actionForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const payload = {
    watch_id: Number(actionModalWatchId),
    kind: "ssh_command",
    config: {
      port: Number(document.getElementById("a-port").value) || 22,
      username: document.getElementById("a-user").value.trim(),
      key_path: document.getElementById("a-key").value.trim(),
      command: document.getElementById("a-cmd").value.trim(),
    },
  };
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

async function refreshAll() {
  await Promise.all([refreshGroups(), refreshNodes(), updateRolePill()]);
}

function onKeySaved() {
  refreshAll();
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
