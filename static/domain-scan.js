// Доменная инвентаризация — ping-скан + WinRM/SMB на каждый живой хост.
// В отличие от обычного скана (scan.js) — фоновый прогон (может занять
// минуты на большой подсети), результат опрашивается поллингом, тот же
// принцип, что у Sweep/Сценариев.

let _dsGroups = [];
let _dsPollTimer = null;
let _dsSelectedScanId = null;

const DS_METHOD_LABELS = { winrm: "WinRM", smb_domain: "SMB (доменная)", smb_anonymous: "SMB (анонимно)" };
const DS_STATUS_LABELS = {
  in_domain: { text: "в домене", color: "var(--ok)" },
  not_in_domain: { text: "не в домене", color: "var(--warn)" },
  error: { text: "ошибка", color: "var(--crit)" },
};

async function refreshDsGroups() {
  try {
    _dsGroups = await api("/api/groups");
  } catch (e) {
    return;
  }
  const opts = _dsGroups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  document.getElementById("ds-group").innerHTML = `<option value="">без группы (глобальные наборы)</option>${opts}`;
  document.getElementById("new-ds-group").innerHTML = `<option value="">любая группа (глобальный)</option>${opts}`;
}

// === Credential-наборы ===

function credSetGroupLabel(s) {
  return s.group_name ? `группа «${s.group_name}»` : "любая группа";
}

async function refreshDsCredSets() {
  const body = document.getElementById("ds-cred-body");
  let sets;
  try {
    sets = await api("/api/domain-scan/credential-sets");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("ds-cred-count").textContent = sets.length;
  if (sets.length === 0) {
    body.innerHTML = `<div class="empty">Наборов нет — заведи хотя бы один ниже, иначе сканировать нечем</div>`;
    return;
  }
  body.innerHTML = sets
    .map(
      (s) => `
      <div class="channel-row">
        <span>
          <b>${escapeHtml(s.label)}</b>
          <span class="count">· ${credSetGroupLabel(s)} · ${escapeHtml(s.range_cidr || "любой диапазон")} · ${DS_METHOD_LABELS[s.method] || s.method}${
        s.fallback_method ? " → " + (DS_METHOD_LABELS[s.fallback_method] || s.fallback_method) : ""
      }${s.username ? " · " + escapeHtml(s.domain || "") + "\\" + escapeHtml(s.username) : ""}</span>
        </span>
        <button data-id="${s.id}" class="del-ds-cred">удалить</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".del-ds-cred").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/domain-scan/credential-sets/${btn.dataset.id}`, { method: "DELETE" });
        toast("Набор удалён");
        refreshDsCredSets();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("new-ds-method").addEventListener("change", (e) => {
  const isAnon = e.target.value === "smb_anonymous";
  ["new-ds-domain", "new-ds-username", "new-ds-password"].forEach((id) => {
    document.getElementById(id).disabled = isAnon;
  });
});

document.getElementById("add-ds-cred").addEventListener("click", async () => {
  const label = document.getElementById("new-ds-label").value.trim();
  const method = document.getElementById("new-ds-method").value;
  if (!label) return toast("Укажи название набора", true);
  const payload = {
    label,
    group_id: document.getElementById("new-ds-group").value ? Number(document.getElementById("new-ds-group").value) : null,
    range_cidr: document.getElementById("new-ds-cidr").value.trim() || null,
    method,
    fallback_method: document.getElementById("new-ds-fallback").value || null,
    domain: document.getElementById("new-ds-domain").value.trim() || null,
    username: document.getElementById("new-ds-username").value.trim() || null,
    password: document.getElementById("new-ds-password").value || null,
  };
  try {
    await api("/api/domain-scan/credential-sets", { method: "POST", body: JSON.stringify(payload) });
    ["new-ds-label", "new-ds-cidr", "new-ds-domain", "new-ds-username", "new-ds-password"].forEach((id) => {
      document.getElementById(id).value = "";
    });
    toast("Набор добавлен");
    refreshDsCredSets();
  } catch (e) {
    toast(e.message, true);
  }
});

// === Сканы ===

async function refreshDsScans() {
  const body = document.getElementById("ds-scans-body");
  let scans;
  try {
    scans = await api("/api/domain-scan");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("ds-scans-count").textContent = scans.length;
  if (scans.length === 0) {
    body.innerHTML = `<div class="empty">Сканов ещё не было</div>`;
    return;
  }
  body.innerHTML = scans
    .map((s) => {
      const statusColor = s.status === "done" ? "var(--ok)" : s.status === "failed" ? "var(--crit)" : "var(--warn)";
      return `
      <div class="channel-row ds-scan-row" data-id="${s.id}" style="cursor:pointer">
        <span><span style="color:${statusColor}">${escapeHtml(s.status)}</span> · ${escapeHtml(s.cidr)}${s.group_name ? " · " + escapeHtml(s.group_name) : ""} <span class="count">· ${s.host_count} хост(ов)</span></span>
        <span class="count">${timeAgo(s.started_at)}</span>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".ds-scan-row").forEach((row) => {
    row.addEventListener("click", () => watchDsScan(Number(row.dataset.id)));
  });
}

function watchDsScan(scanId) {
  _dsSelectedScanId = scanId;
  clearInterval(_dsPollTimer);
  const tick = async () => {
    let data;
    try {
      data = await api(`/api/domain-scan/${scanId}`);
    } catch (e) {
      clearInterval(_dsPollTimer);
      return;
    }
    renderDsResult(data);
    if (data.status !== "running") {
      clearInterval(_dsPollTimer);
      refreshDsScans();
    }
  };
  tick();
  _dsPollTimer = setInterval(tick, 3000);
}

function renderDsResult(data) {
  const meta = document.getElementById("ds-result-meta");
  const body = document.getElementById("ds-result-body");
  if (data.status === "failed") {
    meta.textContent = "";
    body.innerHTML = `<div class="empty">Скан не удался: ${escapeHtml(data.error || "неизвестная ошибка")}</div>`;
    return;
  }
  meta.textContent =
    data.status === "running"
      ? `выполняется · опрошено ${data.hosts.length}${data.live_hosts != null ? " из " + data.live_hosts : ""}`
      : `готово · ${data.hosts.length} хост(ов)`;
  if (data.hosts.length === 0) {
    body.innerHTML = `<div class="empty">${data.status === "running" ? "Ping-скан ещё выполняется…" : "Живых хостов не найдено"}</div>`;
    return;
  }
  body.innerHTML = [...data.hosts]
    .sort((a, b) => naturalCompare(a.address, b.address))
    .map((h) => {
      const st = DS_STATUS_LABELS[h.status] || { text: h.status, color: "var(--text-dim)" };
      const detail = h.status === "error" ? h.error_reason || "" : [h.domain, h.os_caption].filter(Boolean).join(" · ");
      return `<div class="incident-row">
        <span class="sev-dot" style="background:${st.color}"></span>
        <div class="main">
          <div class="label">${escapeHtml(h.computer_name || h.address)} <span class="count">(${escapeHtml(h.address)})</span> <span style="color:${st.color}">${st.text}</span></div>
          <div class="detail">${escapeHtml(detail || "—")}${h.method_used ? ` <span style="opacity:.6">· ${DS_METHOD_LABELS[h.method_used] || h.method_used}</span>` : ""}</div>
        </div>
      </div>`;
    })
    .join("");
}

document.getElementById("ds-run").addEventListener("click", async () => {
  const cidr = document.getElementById("ds-cidr").value.trim();
  if (!cidr) return toast("Укажи CIDR/IP", true);
  const groupId = document.getElementById("ds-group").value;
  const btn = document.getElementById("ds-run");
  btn.disabled = true;
  btn.textContent = "Запускаю…";
  try {
    const started = await api("/api/domain-scan/run", {
      method: "POST",
      body: JSON.stringify({ cidr, group_id: groupId ? Number(groupId) : null }),
    });
    toast("Скан запущен");
    refreshDsScans();
    watchDsScan(started.id);
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Запустить скан";
  }
});

function onKeySaved() {
  refreshDsGroups();
  refreshDsCredSets();
  refreshDsScans();
}

refreshDsGroups();
refreshDsCredSets();
refreshDsScans();
