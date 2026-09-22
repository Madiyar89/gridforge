// Доменная инвентаризация — ping-скан + WinRM/SMB на каждый живой хост.
// Учётки и история сканов — выпадающими списками (по прямому запросу
// пользователя, "как в Advanced Port Scanner"), результат — на главном
// месте, с фильтром по статусу (все/в домене/не в домене/ошибка).

let _dsGroups = [];
let _dsCredSets = [];
let _dsScans = [];
let _dsPollTimer = null;
let _dsSelectedScanId = null;
let _dsCurrentData = null;
let _dsStatusFilter = "";

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

// === Credential-наборы — выпадающий список ===

function credSetOptionLabel(s) {
  const scope = s.group_name ? `группа «${s.group_name}»` : "любая группа";
  const range = s.range_cidr || "любой диапазон";
  const cred = s.username ? ` · ${s.domain || ""}\\${s.username}` : "";
  return `${s.label} — ${scope} · ${range} · ${DS_METHOD_LABELS[s.method] || s.method}${cred}`;
}

async function refreshDsCredSets() {
  const select = document.getElementById("ds-cred-select");
  try {
    _dsCredSets = await api("/api/domain-scan/credential-sets");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
    return;
  }
  document.getElementById("ds-cred-count").textContent = _dsCredSets.length;
  if (_dsCredSets.length === 0) {
    select.innerHTML = `<option value="">Наборов нет — добавь ниже, иначе сканировать нечем</option>`;
    return;
  }
  select.innerHTML = _dsCredSets.map((s) => `<option value="${s.id}">${escapeHtml(credSetOptionLabel(s))}</option>`).join("");
}

document.getElementById("ds-cred-add-toggle").addEventListener("click", () => {
  const form = document.getElementById("ds-cred-form");
  form.hidden = !form.hidden;
});

document.getElementById("ds-cred-delete").addEventListener("click", async () => {
  const id = document.getElementById("ds-cred-select").value;
  if (!id) return toast("Выбери набор для удаления", true);
  const set = _dsCredSets.find((s) => String(s.id) === id);
  if (!confirm(`Удалить набор «${set ? set.label : id}»?`)) return;
  try {
    await api(`/api/domain-scan/credential-sets/${id}`, { method: "DELETE" });
    toast("Набор удалён");
    refreshDsCredSets();
  } catch (e) {
    toast(e.message, true);
  }
});

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
    document.getElementById("ds-cred-form").hidden = true;
    toast("Набор добавлен");
    refreshDsCredSets();
  } catch (e) {
    toast(e.message, true);
  }
});

// === История сканов — выпадающий список ===

async function refreshDsScans() {
  const select = document.getElementById("ds-scans-select");
  try {
    _dsScans = await api("/api/domain-scan");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
    return;
  }
  if (_dsScans.length === 0) {
    select.innerHTML = `<option value="">Сканов ещё не было</option>`;
    return;
  }
  const prev = select.value;
  select.innerHTML = _dsScans
    .map((s) => {
      const label = `${s.status} · ${s.cidr}${s.group_name ? " · " + s.group_name : ""} · ${s.host_count} хост(ов) · ${timeAgo(s.started_at)}`;
      return `<option value="${s.id}">${escapeHtml(label)}</option>`;
    })
    .join("");
  if (prev && _dsScans.some((s) => String(s.id) === prev)) {
    select.value = prev;
  } else {
    select.value = String(_dsScans[0].id);
    watchDsScan(_dsScans[0].id);
  }
}

document.getElementById("ds-scans-select").addEventListener("change", (e) => {
  if (e.target.value) watchDsScan(Number(e.target.value));
});

document.getElementById("ds-result-refresh").addEventListener("click", () => {
  if (_dsSelectedScanId) watchDsScan(_dsSelectedScanId);
});

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
    _dsCurrentData = data;
    renderDsResult();
    if (data.status !== "running") {
      clearInterval(_dsPollTimer);
      refreshDsScans();
    }
  };
  tick();
  _dsPollTimer = setInterval(tick, 3000);
}

// === Результат — с фильтром по статусу (все / в домене / не в домене / ошибка) ===

document.querySelectorAll(".ds-filter-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    _dsStatusFilter = btn.dataset.status;
    document.querySelectorAll(".ds-filter-btn").forEach((b) => b.classList.toggle("active", b === btn));
    renderDsResult();
  });
});

function renderDsResult() {
  const data = _dsCurrentData;
  const meta = document.getElementById("ds-result-meta");
  const body = document.getElementById("ds-result-body");
  if (!data) {
    meta.textContent = "";
    body.innerHTML = `<div class="empty">Выбери скан выше</div>`;
    return;
  }
  if (data.status === "failed") {
    meta.textContent = "";
    body.innerHTML = `<div class="empty">Скан не удался: ${escapeHtml(data.error || "неизвестная ошибка")}</div>`;
    return;
  }
  meta.textContent =
    data.status === "running"
      ? `выполняется · опрошено ${data.hosts.length}${data.live_hosts != null ? " из " + data.live_hosts : ""}`
      : `готово · ${data.hosts.length} хост(ов)`;

  const hosts = _dsStatusFilter ? data.hosts.filter((h) => h.status === _dsStatusFilter) : data.hosts;
  if (hosts.length === 0) {
    body.innerHTML = `<div class="empty">${
      data.hosts.length === 0
        ? data.status === "running"
          ? "Ping-скан ещё выполняется…"
          : "Живых хостов не найдено"
        : "Под этот фильтр ничего не попало"
    }</div>`;
    return;
  }
  body.innerHTML = [...hosts]
    .sort((a, b) => naturalCompare(a.address, b.address))
    .map((h) => {
      const st = DS_STATUS_LABELS[h.status] || { text: h.status, color: "var(--text-dim)" };
      const detail = h.status === "error" ? h.error_reason || "" : [h.domain, h.os_caption].filter(Boolean).join(" · ");
      // Тип устройства — по прямому запросу пользователя ("как определять
      // принтеры/виртуалки"): модель/производитель честно приходят от
      // Windows (Win32_ComputerSystem — говорит "VMware Virtual Platform"
      // для ВМ, реальную модель для физического железа), HTTP-баннер
      // ловит то, что не отвечает ни по WinRM, ни по SMB вообще
      // (принтеры/камеры/веб-морды свитчей).
      const deviceBits = [];
      if (h.manufacturer || h.model) deviceBits.push([h.manufacturer, h.model].filter(Boolean).join(" "));
      if (h.http_banner) deviceBits.push(`HTTP: ${h.http_banner}`);
      const deviceLine = deviceBits.length ? `<div class="detail" style="color:var(--accent)">${escapeHtml(deviceBits.join(" · "))}</div>` : "";
      return `<div class="incident-row">
        <span class="sev-dot" style="background:${st.color}"></span>
        <div class="main">
          <div class="label">${escapeHtml(h.computer_name || h.address)} <span class="count">(${escapeHtml(h.address)})</span> <span style="color:${st.color}">${st.text}</span></div>
          <div class="detail">${escapeHtml(detail || "—")}${h.method_used ? ` <span style="opacity:.6">· ${DS_METHOD_LABELS[h.method_used] || h.method_used}</span>` : ""}</div>
          ${deviceLine}
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
    await refreshDsScans();
    document.getElementById("ds-scans-select").value = String(started.id);
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
