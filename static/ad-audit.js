// AD-аудит — новый безстейтовый отчёт по категориям (риск-скор из
// ad_audit_rules.py, 25 правил, рендер общий с сетевым аудитом —
// см. risk-report.js) + старый разовый прогон (без сохранения
// подключения, оставлен для обратной совместимости).

const adReportPanel = createRiskReportPanel(
  "ad",
  async () => {
    try {
      return await api("/api/ad-audit/report");
    } catch (e) {
      return null;
    }
  },
  "Домен",
  "domains",
  'Нет доменов — добавь LDAP-подключение на странице <a href="ldap.html">LDAP</a>'
);

function loadAdReport() {
  return adReportPanel.load();
}

document.getElementById("legacy-toggle").addEventListener("click", () => {
  const body = document.getElementById("legacy-body");
  body.hidden = !body.hidden;
});

// === старый разовый прогон (без сохранения подключения) ===

function renderAdFindings(findings) {
  document.getElementById("ad-findings-count").textContent = findings.length;
  const body = document.getElementById("ad-findings-body");
  if (findings.length === 0) {
    body.innerHTML = `<div class="empty">Находок нет</div>`;
    return;
  }
  body.innerHTML = findings
    .map(
      (f) => `
      <div class="incident-row">
        <span class="sev-dot ${f.severity}"></span>
        <div class="main">
          <div class="label">${escapeHtml(f.check_name)}</div>
          <div class="detail">${escapeHtml(f.detail)}</div>
          <div class="detail" style="opacity:.6">${escapeHtml(f.dn)}</div>
        </div>
      </div>`
    )
    .join("");
}

async function refreshRuns() {
  const body = document.getElementById("runs-body");
  let runs;
  try {
    runs = await api("/api/ad-audit/runs");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("runs-count").textContent = runs.length;
  if (runs.length === 0) {
    body.innerHTML = `<div class="empty">Прогонов ещё не было</div>`;
    return;
  }
  body.innerHTML = runs
    .map((r) => {
      const status = r.ok ? `<span style="color:var(--ok)">ok</span>` : `<span style="color:var(--crit)">${escapeHtml(r.error || "ошибка")}</span>`;
      return `
      <div class="channel-row" data-id="${r.id}" style="cursor:pointer">
        <span>${escapeHtml(r.server)} · ${escapeHtml(r.search_base)} <span class="count">· ${status} · ${r.finding_count} находок</span></span>
        <span class="count">${timeAgo(r.started_at)}</span>
      </div>`;
    })
    .join("");
  body.querySelectorAll("[data-id]").forEach((row) => {
    row.addEventListener("click", async () => {
      try {
        renderAdFindings(await api(`/api/ad-audit/runs/${row.dataset.id}/findings`));
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("run-ad-audit").addEventListener("click", async () => {
  const server = document.getElementById("a-server").value.trim();
  const base = document.getElementById("a-base").value.trim();
  const bindDn = document.getElementById("a-binddn").value.trim();
  const bindPass = document.getElementById("a-bindpass").value;
  const port = Number(document.getElementById("a-port").value) || 636;
  if (!server || !base || !bindDn || !bindPass) return toast("Заполни все поля", true);

  const btn = document.getElementById("run-ad-audit");
  btn.disabled = true;
  btn.textContent = "Проверяю…";
  try {
    const result = await api("/api/ad-audit", {
      method: "POST",
      body: JSON.stringify({ server, port, bind_dn: bindDn, bind_password: bindPass, search_base: base }),
    });
    if (!result.ok) {
      toast("Ошибка подключения: " + result.error, true);
    } else {
      renderAdFindings(result.findings);
      const bad = result.findings.filter((f) => f.severity !== "info").length;
      toast(bad === 0 ? "Аудит завершён — критичных находок нет" : `Аудит: ${result.findings.length} находок`, bad > 0);
    }
    refreshRuns();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Прогнать аудит";
  }
});

function onKeySaved() {
  loadAdReport();
  refreshRuns();
}

loadAdReport();
refreshRuns();
