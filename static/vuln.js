// Проверка на уязвимости — nmap-профили на узлах группы + накопительный
// .xlsx-реестр под официальный бланк. Перенос функции NetOpsHub.

const VULN_RESPONSIBLE_KEY = "gridforge_vuln_responsible";
let _vulnGroupId = null;
let _vulnScanId = null;

async function refreshVulnGroups() {
  const select = document.getElementById("vuln-group-select");
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  const previous = select.value;
  select.innerHTML =
    `<option value="">выбери группу…</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  if (previous) select.value = previous;
}

document.getElementById("vuln-group-select").addEventListener("change", onVulnGroupChange);

function onVulnGroupChange() {
  _vulnGroupId = document.getElementById("vuln-group-select").value || null;
  _vulnScanId = null;
  document.getElementById("vuln-hosts-body").innerHTML = `<div class="empty">Выбери скан слева</div>`;
  document.getElementById("vuln-hosts-count").textContent = "";
  if (!_vulnGroupId) {
    document.getElementById("vuln-profile-grid").innerHTML = `<div class="empty">Выбери группу выше</div>`;
    document.getElementById("vuln-scans-body").innerHTML = `<div class="empty">Выбери группу выше</div>`;
    document.getElementById("vuln-register-table").innerHTML = `<tbody><tr><td class="empty">Выбери группу выше</td></tr></tbody>`;
    document.getElementById("vuln-register-download").removeAttribute("data-href");
    return;
  }
  refreshVulnAll();
}

const responsibleInput = document.getElementById("vuln-responsible");
responsibleInput.value = localStorage.getItem(VULN_RESPONSIBLE_KEY) || "";
responsibleInput.addEventListener("change", () => {
  localStorage.setItem(VULN_RESPONSIBLE_KEY, responsibleInput.value.trim());
});

const PROFILE_ORDER = ["ping", "quick", "full_ports", "vuln", "os"];

async function refreshVulnProfiles() {
  const grid = document.getElementById("vuln-profile-grid");
  if (!_vulnGroupId) return;
  let summary;
  try {
    summary = await api(`/api/groups/${_vulnGroupId}/vuln-scans/summary`);
  } catch (e) {
    grid.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  const byProfile = Object.fromEntries(summary.map((s) => [s.profile, s]));
  grid.innerHTML = PROFILE_ORDER.map((key) => {
    const row = byProfile[key];
    const scan = row.scan;
    let last = "ни разу не запускался";
    let findingsHtml = "";
    if (scan) {
      if (scan.status === "running") {
        last = `выполняется — начат ${timeAgo(scan.started_at)}`;
      } else if (scan.status === "failed") {
        last = `<span style="color:var(--crit)">ошибка — ${escapeHtml(scan.error || "")}</span>`;
      } else {
        last = `завершён ${timeAgo(scan.finished_at || scan.started_at)}, хостов: ${scan.host_count}`;
        const cls = scan.findings_count > 0 ? "findings-n has" : "findings-n";
        findingsHtml = `<div class="${cls}">находок: ${scan.findings_count}</div>`;
      }
    }
    const running = scan && scan.status === "running";
    return `
      <div class="vuln-profile-card">
        <span class="label">${escapeHtml(row.label)}</span>
        <span class="last">${last}</span>
        ${findingsHtml}
        <button type="button" class="btn-ghost run-profile" data-profile="${key}" ${running ? "disabled" : ""}>
          ${running ? "уже выполняется…" : "Запустить"}
        </button>
      </div>`;
  }).join("");

  grid.querySelectorAll(".run-profile").forEach((btn) => {
    btn.addEventListener("click", () => runVulnProfile(btn.dataset.profile));
  });
}

async function runVulnProfile(profile) {
  if (!_vulnGroupId) return toast("Выбери группу", true);
  try {
    const result = await api(`/api/groups/${_vulnGroupId}/vuln-scans`, {
      method: "POST",
      body: JSON.stringify({ profile, responsible: responsibleInput.value.trim() || null }),
    });
    toast(`Скан запущен — целей: ${result.targets}`);
    refreshVulnAll();
  } catch (e) {
    toast(e.message, true);
  }
}

async function refreshVulnScans() {
  const body = document.getElementById("vuln-scans-body");
  if (!_vulnGroupId) return;
  let scans;
  try {
    scans = await api(`/api/groups/${_vulnGroupId}/vuln-scans`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("vuln-scans-count").textContent = scans.length;
  if (scans.length === 0) {
    body.innerHTML = `<div class="empty">Сканов ещё не было</div>`;
    return;
  }
  const STATUS_LABEL = { running: "выполняется", done: "завершён", failed: "ошибка" };
  body.innerHTML = scans
    .map((s) => {
      const findingsBit = s.status === "done" && s.findings_count > 0
        ? `<span style="color:var(--crit)"> · находок: ${s.findings_count}</span>`
        : "";
      return `
        <div class="vuln-scan-row${String(s.id) === String(_vulnScanId) ? " active" : ""}" data-id="${s.id}">
          <div class="top">
            <span>${escapeHtml(s.profile_label)}</span>
            <span>${STATUS_LABEL[s.status] || s.status}</span>
          </div>
          <div class="meta">${timeAgo(s.started_at)} · хостов: ${s.host_count}${findingsBit}${s.responsible ? " · " + escapeHtml(s.responsible) : ""}</div>
        </div>`;
    })
    .join("");
  body.querySelectorAll(".vuln-scan-row").forEach((el) => {
    el.addEventListener("click", () => loadVulnScanHosts(el.dataset.id));
  });
}

async function loadVulnScanHosts(scanId) {
  _vulnScanId = scanId;
  refreshVulnScans();
  const body = document.getElementById("vuln-hosts-body");
  body.innerHTML = `<div class="empty">Загрузка…</div>`;
  let hosts;
  try {
    hosts = await api(`/api/vuln-scans/${scanId}/hosts`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("vuln-hosts-count").textContent = hosts.length;
  if (hosts.length === 0) {
    body.innerHTML = `<div class="empty">Хостов не отвечало</div>`;
    return;
  }
  body.innerHTML = hosts
    .map((h) => {
      const findings = (h.findings || []).filter((f) => f.severity !== "info");
      const findingsHtml = findings.length
        ? findings
            .map(
              (f) => `
              <div class="vuln-finding">
                <span class="sev-badge ${f.severity}">${escapeHtml(f.severity)}</span>
                <span style="font-family:var(--mono);color:var(--text-dim)"> ${escapeHtml(f.port || "")}</span>
                <div class="summary">${escapeHtml(f.summary || "")}</div>
                ${f.cves && f.cves.length ? `<div class="cves">${f.cves.map(escapeHtml).join(", ")}</div>` : ""}
              </div>`
            )
            .join("")
        : `<div class="vuln-finding" style="color:var(--text-dim)">находок нет</div>`;
      return `
        <div class="vuln-host-block">
          <span class="addr">${escapeHtml(h.address)}${h.hostname ? " (" + escapeHtml(h.hostname) + ")" : ""}</span>
          ${findingsHtml}
        </div>`;
    })
    .join("");
}

async function refreshVulnRegister() {
  const table = document.getElementById("vuln-register-table");
  const downloadBtn = document.getElementById("vuln-register-download");
  if (!_vulnGroupId) return;
  downloadBtn.setAttribute("data-href", `/api/groups/${_vulnGroupId}/vuln-register.xlsx`);
  let data;
  try {
    data = await api(`/api/groups/${_vulnGroupId}/vuln-register`);
  } catch (e) {
    table.innerHTML = `<tbody><tr><td class="empty">${emptyOrError(e)}</td></tr></tbody>`;
    return;
  }
  if (data.rows.length === 0) {
    table.innerHTML = `<tbody><tr><td class="empty">Реестр пока пуст</td></tr></tbody>`;
    return;
  }
  const thead = `<thead><tr>${data.headers.map((h) => `<th>${escapeHtml(h)}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${data.rows
    .map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(cell ?? "")}</td>`).join("")}</tr>`)
    .join("")}</tbody>`;
  table.innerHTML = thead + tbody;
}

document.getElementById("vuln-register-download").addEventListener("click", (ev) => {
  const href = ev.currentTarget.getAttribute("data-href");
  if (!href) return toast("Выбери группу", true);
  window.location.href = href;
});

function refreshVulnAll() {
  refreshVulnProfiles();
  refreshVulnScans();
  refreshVulnRegister();
}

function onKeySaved() {
  refreshVulnGroups();
}

refreshVulnGroups();
setInterval(() => {
  if (_vulnGroupId) refreshVulnAll();
}, REFRESH_MS);
