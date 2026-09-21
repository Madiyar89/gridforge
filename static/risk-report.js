// Общий рендер риск-скор отчёта (категории -> правила -> баллы) —
// используется и AD-аудитом (домены), и сетевым аудитом (устройства).
// Один и тот же JSON-контракт с сервера: {risk_score, risk_band,
// categories:[{name, score, rules:[{id, severity, points, name,
// description, fix, objects}]}]}.

function riskBandKey(band) {
  if (band === "низкий") return "low";
  if (band === "средний") return "medium";
  if (band === "высокий") return "high";
  return "critical";
}

// idPrefix — общая часть id элементов на странице ("ad" / "net"), ожидает
// разметку: #{idPrefix}-report-fleet(-body), #{idPrefix}-report-domain(-body),
// #{idPrefix}-report-meta, #{idPrefix}-report-refresh, #{idPrefix}-domain-back.
// fetchReport — async () => отчёт или null при ошибке.
// rowLabel — заголовок строки списка ("Домен"/"Устройство").
// itemsKey — ключ массива объектов в отчёте ("domains"/"devices").
function createRiskReportPanel(idPrefix, fetchReport, rowLabel, itemsKey, emptyMessage) {
  let report = null;

  function el(suffix) {
    return document.getElementById(`${idPrefix}-${suffix}`);
  }

  async function load() {
    const metaEl = el("report-meta");
    const body = el("report-fleet-body");
    el("report-domain").hidden = true;
    el("report-fleet").hidden = false;
    metaEl.textContent = "проверяю…";
    body.innerHTML = "";
    const fetched = await fetchReport();
    if (fetched === null) {
      metaEl.textContent = "";
      body.innerHTML = `<div class="empty">Не удалось получить отчёт</div>`;
      return;
    }
    report = fetched;
    let metaText = `каталог правил v${report.catalog_version} (${report.catalog_updated_at})`;
    const problems = report.errors || report.skipped_no_backup;
    if (problems && problems.length > 0) {
      const label = report.errors ? "ошибки" : "без бэкапа";
      const list = report.errors
        ? report.errors.map((e) => `${e.label}: ${e.error}`).join("; ")
        : problems.join(", ");
      metaText += ` · ${label}: ${list}`;
    }
    metaEl.textContent = metaText;
    renderList();
  }

  function renderList() {
    const body = el("report-fleet-body");
    const items = report[itemsKey] || [];
    if (items.length === 0) {
      body.innerHTML = `<div class="empty">${emptyMessage || "Нет данных для отчёта"}</div>`;
      return;
    }
    body.innerHTML = items
      .map(
        (d, i) => `
      <div class="domain-row" data-i="${i}">
        <div>
          <div class="name">${escapeHtml(d.label || d.id)}</div>
          <div class="sub">${escapeHtml(d.domain || d.address || "")}</div>
        </div>
        <div style="text-align:right">
          <div class="score">${d.risk_score}</div>
          <span class="risk-band ${riskBandKey(d.risk_band)}">${escapeHtml(d.risk_band)}</span>
        </div>
      </div>`
      )
      .join("");
    body.querySelectorAll("[data-i]").forEach((row) => {
      row.addEventListener("click", () => showItem(Number(row.dataset.i)));
    });
  }

  function showItem(i) {
    const items = report[itemsKey] || [];
    const d = items[i];
    if (!d) return;

    let tiles = "";
    d.categories.forEach((c) => {
      tiles += `<div class="risk-tile">
        <div class="t-title">${escapeHtml(c.name)}</div>
        <div class="t-score risk-band ${riskBandKey(riskBand(c.score))}" style="display:inline-block">${c.score} / 100</div>
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
          <span class="risk-band ${riskBandKey(riskBand(c.score))}">${c.score} / 100</span>
        </div>
        ${rows}
      </div>`;
    });

    el("report-domain-body").innerHTML = `
      <div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
        <div>
          <div style="font-weight:600;font-size:15px">${escapeHtml(d.label || d.id)}</div>
          <div class="sub" style="color:var(--text-dim);font-family:var(--mono);font-size:11.5px">${escapeHtml(d.domain || d.address || "")}</div>
        </div>
        <div style="text-align:right">
          <div class="score" style="font-size:24px">${d.risk_score}</div>
          <span class="risk-band ${riskBandKey(d.risk_band)}">${escapeHtml(d.risk_band)}</span>
        </div>
      </div>
      <div class="risk-tiles">${tiles}</div>
      ${sections}
    `;
    el("report-fleet").hidden = true;
    el("report-domain").hidden = false;
  }

  function riskBand(score) {
    if (score <= 25) return "низкий";
    if (score <= 50) return "средний";
    if (score <= 75) return "высокий";
    return "критический";
  }

  el("report-refresh").addEventListener("click", load);
  el("domain-back").addEventListener("click", () => {
    el("report-domain").hidden = true;
    el("report-fleet").hidden = false;
  });

  return { load, rowLabel };
}
