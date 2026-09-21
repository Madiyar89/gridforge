// AD-аудит — новый безстейтовый отчёт по категориям (риск-скор из
// ad_audit_rules.py, 25 правил) + старый разовый прогон (без сохранения
// подключения, оставлен для обратной совместимости).

function riskBandKey(band) {
  if (band === "низкий") return "low";
  if (band === "средний") return "medium";
  if (band === "высокий") return "high";
  return "critical";
}

let currentReport = null;

async function loadAdReport() {
  const metaEl = document.getElementById("report-meta");
  const body = document.getElementById("report-fleet-body");
  document.getElementById("report-domain").hidden = true;
  document.getElementById("report-fleet").hidden = false;
  metaEl.textContent = "проверяю…";
  body.innerHTML = "";
  let report;
  try {
    report = await api("/api/ad-audit/report");
  } catch (e) {
    metaEl.textContent = "";
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  currentReport = report;
  let metaText = `каталог правил v${report.catalog_version} (${report.catalog_updated_at})`;
  if ((report.errors || []).length > 0) {
    metaText += ` · ошибки: ${report.errors.map((e) => `${e.label}: ${e.error}`).join("; ")}`;
  }
  metaEl.textContent = metaText;
  renderDomainList();
}

function renderDomainList() {
  const body = document.getElementById("report-fleet-body");
  const domains = currentReport.domains || [];
  if (domains.length === 0) {
    body.innerHTML = '<div class="empty">Нет доменов — добавь LDAP-подключение на странице <a href="ldap.html">LDAP</a></div>';
    return;
  }
  body.innerHTML = domains
    .map(
      (d, i) => `
    <div class="domain-row" data-i="${i}">
      <div>
        <div class="name">${escapeHtml(d.label)}</div>
        <div class="sub">${escapeHtml(d.domain)}</div>
      </div>
      <div style="text-align:right">
        <div class="score">${d.risk_score}</div>
        <span class="risk-band ${riskBandKey(d.risk_band)}">${escapeHtml(d.risk_band)}</span>
      </div>
    </div>`
    )
    .join("");
  body.querySelectorAll("[data-i]").forEach((row) => {
    row.addEventListener("click", () => showDomain(Number(row.dataset.i)));
  });
}

function showDomain(i) {
  const d = currentReport.domains[i];
  if (!d) return;

  let tiles = "";
  d.categories.forEach((c) => {
    tiles += `<div class="risk-tile">
      <div class="t-title">${escapeHtml(c.name)}</div>
      <div class="t-score risk-band ${riskBandKey(riskBandOf(c.score))}" style="display:inline-block">${c.score} / 100</div>
    </div>`;
  });

  let sections = "";
  d.categories.forEach((c) => {
    const rules = c.rules.slice().sort((a, b) => b.points - a.points);
    let rows = "";
    rules.forEach((r) => {
      const objectsBlock = (r.objects || []).length
        ? `<details class="risk-details" open><summary>Затронуто: ${r.objects.length}</summary><div class="risk-objects">${r.objects.map((o) => `<div>${escapeHtml(o)}</div>`).join("")}</div></details>`
        : "";
      const fixBlock = r.points > 0 ? `<div class="risk-fix">${escapeHtml(r.fix)}</div>` : "";
      rows += `<div class="risk-rule-row">
        <div class="pts" style="color:${r.points > 0 ? "var(--crit)" : "var(--ok)"}">${r.points}</div>
        <div style="flex:1;min-width:0">
          <div class="name">${escapeHtml(r.name)}</div>
          <div class="desc">${escapeHtml(r.description)}</div>
          ${objectsBlock}
          ${fixBlock}
        </div>
      </div>`;
    });
    sections += `<div class="risk-cat-section">
      <div class="risk-cat-head">
        <span>${escapeHtml(c.name)}</span>
        <span class="risk-band ${riskBandKey(riskBandOf(c.score))}">${c.score} / 100</span>
      </div>
      ${rows}
    </div>`;
  });

  document.getElementById("report-domain-body").innerHTML = `
    <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
      <div>
        <div style="font-weight:600;font-size:15px">${escapeHtml(d.label)}</div>
        <div class="sub" style="color:var(--text-dim);font-family:var(--mono);font-size:11.5px">${escapeHtml(d.domain)}</div>
      </div>
      <div style="text-align:right">
        <div class="score" style="font-size:24px">${d.risk_score}</div>
        <span class="risk-band ${riskBandKey(d.risk_band)}">${escapeHtml(d.risk_band)}</span>
      </div>
    </div>
    <div class="risk-tiles">${tiles}</div>
    ${sections}
  `;
  document.getElementById("report-fleet").hidden = true;
  document.getElementById("report-domain").hidden = false;
}

function riskBandOf(score) {
  if (score <= 25) return "низкий";
  if (score <= 50) return "средний";
  if (score <= 75) return "высокий";
  return "критический";
}

document.getElementById("report-refresh").addEventListener("click", loadAdReport);
document.getElementById("domain-back").addEventListener("click", () => {
  document.getElementById("report-domain").hidden = true;
  document.getElementById("report-fleet").hidden = false;
});
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
