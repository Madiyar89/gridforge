// Трафик по потокам (NetFlow v9) — топ говорящих, топ пар, лента потоков.

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
          <span class="talker-addr">${escapeHtml(t.address)}${geo}</span>
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
        <span>${escapeHtml(p.src_addr)} → ${escapeHtml(p.dst_addr)}</span>
        <span>${formatBytes(p.bytes)} · ${p.packets} пак.</span>
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
        <span>${time} · ${escapeHtml(f.src_addr)}${srcPort} → ${escapeHtml(f.dst_addr)}${dstPort} · ${proto}</span>
        <span>${formatBytes(f.byte_count)}</span>
      </div>`;
    })
    .join("");
}

function refreshAll() {
  refreshTalkers();
  refreshPairs();
  refreshFlowsList();
}

document.getElementById("refresh-flows").addEventListener("click", refreshAll);
document.getElementById("window-select").addEventListener("change", refreshAll);

function onKeySaved() {
  refreshAll();
}

refreshAll();
setInterval(refreshAll, REFRESH_MS);
