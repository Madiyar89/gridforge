// Трафик по потокам (NetFlow v9) — топ говорящих, топ пар, топ протоколов,
// лента потоков, оповещения по порогу трафика.

const PROTOCOL_NAMES = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP" };

function formatBytes(n) {
  if (n < 1024) return `${n} Б`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} КБ`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} МБ`;
  return `${(n / 1024 ** 3).toFixed(2)} ГБ`;
}

function currentMinutes() {
  return Number(document.getElementById("window-select").value);
}

function addrLabel(addr, nodeName) {
  return nodeName ? `${escapeHtml(nodeName)} <span class="talker-geo">(${escapeHtml(addr)})</span>` : escapeHtml(addr);
}

async function refreshTalkers() {
  const body = document.getElementById("talkers-body");
  const minutes = currentMinutes();
  let talkers;
  try {
    talkers = await api(`/api/flows/top-talkers?minutes=${minutes}&limit=15`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("talkers-count").textContent = talkers.length;
  if (talkers.length === 0) {
    body.innerHTML = `<div class="empty">Потоков за этот период нет — проверь, что экспорт NetFlow настроен на порт ${document.getElementById("netflow-port").textContent}</div>`;
    return;
  }
  const maxBytes = talkers[0].bytes || 1;
  body.innerHTML = talkers
    .map((t) => {
      const geo = t.geo ? `<span class="talker-geo">${escapeHtml(t.geo.country || "")}${t.geo.as_org ? " · " + escapeHtml(t.geo.as_org) : ""}</span>` : "";
      const pct = Math.max(2, Math.round((t.bytes / maxBytes) * 100));
      return `<div class="talker-row">
        <div class="talker-head">
          <span class="talker-addr">${addrLabel(t.address, t.node_name)}${geo}</span>
          <span class="talker-bytes">${formatBytes(t.bytes)}</span>
        </div>
        <div class="talker-bar"><div class="talker-bar-fill" style="width:${pct}%"></div></div>
      </div>`;
    })
    .join("");
}

async function refreshPairs() {
  const body = document.getElementById("pairs-body");
  const minutes = currentMinutes();
  let pairs;
  try {
    pairs = await api(`/api/flows/top-pairs?minutes=${minutes}&limit=15`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("pairs-count").textContent = pairs.length;
  if (pairs.length === 0) {
    body.innerHTML = `<div class="empty">Нет данных за этот период</div>`;
    return;
  }
  body.innerHTML = pairs
    .map(
      (p) => `<div class="pair-row">
        <span>${addrLabel(p.src_addr, p.src_node_name)} → ${addrLabel(p.dst_addr, p.dst_node_name)}</span>
        <span>${formatBytes(p.bytes)} · ${p.packets} пак.</span>
      </div>`
    )
    .join("");
}

async function refreshProtocols() {
  const body = document.getElementById("protocols-body");
  const minutes = currentMinutes();
  let rows;
  try {
    rows = await api(`/api/flows/top-protocols?minutes=${minutes}&limit=10`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("protocols-count").textContent = rows.length;
  if (rows.length === 0) {
    body.innerHTML = `<div class="empty">Нет данных за этот период</div>`;
    return;
  }
  body.innerHTML = rows
    .map(
      (r) => `<div class="proto-row">
        <span class="name">${escapeHtml(r.protocol_name)}</span>
        <span>${formatBytes(r.bytes)} · ${r.packets} пак.</span>
      </div>`
    )
    .join("");
}

async function refreshFlowsList() {
  const body = document.getElementById("flows-body");
  const minutes = currentMinutes();
  let flows;
  try {
    flows = await api(`/api/flows?minutes=${minutes}&limit=100`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("flows-count").textContent = flows.length;
  if (flows.length === 0) {
    body.innerHTML = `<div class="empty">Пусто</div>`;
    return;
  }
  body.innerHTML = flows
    .map((f) => {
      const proto = f.protocol != null ? PROTOCOL_NAMES[f.protocol] || `#${f.protocol}` : "?";
      const srcPort = f.src_port != null ? `:${f.src_port}` : "";
      const dstPort = f.dst_port != null ? `:${f.dst_port}` : "";
      const time = new Date(f.received_at).toLocaleTimeString("ru-RU");
      return `<div class="pair-row">
        <span>${time} · ${addrLabel(f.src_addr, f.src_node_name)}${srcPort} → ${addrLabel(f.dst_addr, f.dst_node_name)}${dstPort} · ${proto} · экспортёр ${escapeHtml(f.exporter_ip)}</span>
        <span>${formatBytes(f.byte_count)}</span>
      </div>`;
    })
    .join("");
}

function refreshAll() {
  refreshTalkers();
  refreshPairs();
  refreshProtocols();
  refreshFlowsList();
}

document.getElementById("refresh-flows").addEventListener("click", refreshAll);
document.getElementById("window-select").addEventListener("change", refreshAll);

// --- Оповещения по порогу трафика (FlowAlertRule) ---

async function loadFlowAlertPickers() {
  const nodeSelect = document.getElementById("fa-node");
  const channelSelect = document.getElementById("fa-channel");
  try {
    const nodes = sortNodesNatural(await api("/api/nodes"));
    nodeSelect.innerHTML = `<option value="">выбери узел…</option>` + nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)} (${escapeHtml(n.address)})</option>`).join("");
  } catch (e) {
    nodeSelect.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
  try {
    const channels = await api("/api/channels");
    channelSelect.innerHTML = channels.length
      ? channels.map((c) => `<option value="${c.id}">#${c.id} · ${escapeHtml(c.kind)}</option>`).join("")
      : `<option value="">сначала заведи канал (Настройки → Каналы)</option>`;
  } catch (e) {
    channelSelect.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
}

async function refreshFlowAlertRules() {
  const body = document.getElementById("fa-rules-body");
  let rules;
  try {
    rules = await api("/api/flow-alert-rules");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (rules.length === 0) {
    body.innerHTML = `<div class="empty">Правил ещё нет</div>`;
    return;
  }
  body.innerHTML = rules
    .map((r) => {
      const last = r.last_triggered_at ? `последнее срабатывание: ${new Date(r.last_triggered_at).toLocaleString("ru-RU")}` : "ещё не срабатывало";
      return `<div class="pair-row">
        <span><b>${escapeHtml(r.label)}</b> · ${escapeHtml(r.node_name || "узел #" + r.node_id)} · порог ${formatBytes(r.bytes_threshold)} / ${r.window_minutes} мин · ${last}</span>
        <button type="button" class="btn-ghost del-fa-rule" data-id="${r.id}">удалить</button>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".del-fa-rule").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/flow-alert-rules/${btn.dataset.id}`, { method: "DELETE" });
        toast("Правило удалено");
        refreshFlowAlertRules();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("fa-add").addEventListener("click", async () => {
  const node_id = Number(document.getElementById("fa-node").value);
  const label = document.getElementById("fa-label").value.trim();
  const thresholdMb = Number(document.getElementById("fa-threshold").value);
  const window_minutes = Number(document.getElementById("fa-window").value) || 15;
  const channel_id = Number(document.getElementById("fa-channel").value);
  if (!node_id) return toast("Выбери узел", true);
  if (!label) return toast("Укажи название правила", true);
  if (!thresholdMb || thresholdMb <= 0) return toast("Укажи порог в МБ", true);
  if (!channel_id) return toast("Выбери канал", true);
  try {
    await api("/api/flow-alert-rules", {
      method: "POST",
      body: JSON.stringify({ node_id, label, bytes_threshold: Math.round(thresholdMb * 1024 * 1024), window_minutes, channel_id }),
    });
    document.getElementById("fa-label").value = "";
    document.getElementById("fa-threshold").value = "";
    toast("Правило добавлено");
    refreshFlowAlertRules();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshAll();
  loadFlowAlertPickers();
  refreshFlowAlertRules();
}

refreshAll();
loadFlowAlertPickers();
refreshFlowAlertRules();
setInterval(refreshAll, REFRESH_MS);
