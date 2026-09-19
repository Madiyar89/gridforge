// Скан сети — запуск, история, найденные хосты, создание Node из хоста.

let selectedScanId = null;

async function refreshScans() {
  const body = document.getElementById("scans-body");
  let scans;
  try {
    scans = await api("/api/scans");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("scans-count").textContent = scans.length;
  if (scans.length === 0) {
    body.innerHTML = `<div class="empty">Сканов ещё не было</div>`;
    return;
  }
  body.innerHTML = scans
    .map((s) => {
      const statusColor = s.status === "done" ? "var(--ok)" : s.status === "failed" ? "var(--crit)" : "var(--warn)";
      return `
      <div class="channel-row scan-row" data-id="${s.id}" style="cursor:pointer">
        <span><span style="color:${statusColor}">${escapeHtml(s.status)}</span> · ${escapeHtml(s.cidr)} <span class="count">· ${s.host_count} хост(ов)</span></span>
        <span class="count">${timeAgo(s.started_at)}</span>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".scan-row").forEach((row) => {
    row.addEventListener("click", () => selectScan(row.dataset.id));
  });
}

async function selectScan(scanId) {
  selectedScanId = scanId;
  const body = document.getElementById("hosts-body");
  body.innerHTML = `<div class="empty">Загрузка…</div>`;
  let hosts;
  try {
    hosts = await api(`/api/scans/${scanId}/hosts`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("hosts-count").textContent = hosts.length;
  if (hosts.length === 0) {
    body.innerHTML = `<div class="empty">Живых хостов не найдено</div>`;
    return;
  }
  body.innerHTML = hosts
    .map((h) => {
      const ports = h.open_ports.map((p) => `${p.port}${p.service ? "/" + p.service : ""}`).join(", ") || "нет открытых портов";
      const action = h.already_node
        ? `<span class="count">уже в инвентаре</span>`
        : `<button data-id="${h.id}" data-addr="${escapeHtml(h.address)}" data-hostname="${escapeHtml(h.hostname || "")}" class="make-node">+ в инвентарь</button>`;
      return `
        <div class="channel-row">
          <span>${escapeHtml(h.hostname || h.address)} ${h.hostname ? `<span class="count">(${escapeHtml(h.address)})</span>` : ""} <span class="count">· ${escapeHtml(ports)}</span></span>
          ${action}
        </div>`;
    })
    .join("");
  body.querySelectorAll(".make-node").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/scan-hosts/${btn.dataset.id}/create-node`, {
          method: "POST",
          body: JSON.stringify({ name: btn.dataset.hostname || null }),
        });
        toast("Узел добавлен в инвентарь");
        selectScan(selectedScanId);
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("run-scan").addEventListener("click", async () => {
  const cidr = document.getElementById("scan-cidr").value.trim();
  const ports = document.getElementById("scan-ports").value.trim();
  if (!cidr) return toast("Укажи CIDR/IP", true);
  const btn = document.getElementById("run-scan");
  btn.disabled = true;
  btn.textContent = "Сканирую…";
  try {
    const result = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify({ cidr, ports: ports || null }),
    });
    if (result.status === "failed") {
      toast("Скан не удался: " + result.error, true);
    } else {
      toast(`Скан завершён: ${result.host_count} хост(ов)`);
    }
    await refreshScans();
    if (result.id) selectScan(result.id);
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Сканировать";
  }
});

function onKeySaved() {
  refreshScans();
}

refreshScans();
