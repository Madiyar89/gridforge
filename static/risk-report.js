// Общий рендер риск-скор отчёта (категории -> правила -> баллы) —
// используется и AD-аудитом (домены), и сетевым аудитом (устройства).
// Один и тот же JSON-контракт с сервера: {risk_score, risk_band,
// categories:[{name, score, rules:[{id, severity, points, name,
// description, fix, objects}]}]}.
//
// Вёрстка/логика намеренно повторяют старый прототип на NetOpsHub
// (createAuditPanel в compliance-audit.js) — тот же порядок элементов
// (плитки категорий с "N нарушений", радар, таблица правил "Баллы |
// Правило" с раскрывающимся "Затронуто"/"Как исправить"), по прямому
// запросу пользователя ("сделай отображение как на фото 4").

function riskBandKey(band) {
  if (band === "низкий") return "low";
  if (band === "средний") return "medium";
  if (band === "высокий") return "high";
  return "critical";
}

function riskBandOf(score) {
  if (score <= 25) return "низкий";
  if (score <= 50) return "средний";
  if (score <= 75) return "высокий";
  return "критический";
}

function riskRadarSvg(categories) {
  const n = categories.length;
  if (n < 3) return ""; // радар нечитаем меньше чем на 3 осях
  const cx = 200, cy = 165, R = 90;
  // Без "рамки" сетки (полноценных колец-диамантов) — при низких баллах
  // почти по всем осям (частый случай) толстая внешняя рамка визуально
  // забивала едва заметный многоугольник данных, отчёт читался как
  // "пустая рамка", а не как диаграмма. Вместо колец — только тонкие
  // спицы-оси и подписанные баллом точки на каждой вершине, так число
  // видно даже когда сама фигура почти не видна у центра.
  let axes = "", labels = "", dots = "", pts = [];
  categories.forEach((c, i) => {
    const a = -Math.PI / 2 + i * ((2 * Math.PI) / n);
    const x2 = cx + R * Math.cos(a), y2 = cy + R * Math.sin(a);
    axes += `<line x1="${cx}" y1="${cy}" x2="${x2}" y2="${y2}" stroke="var(--border)" stroke-width="1" stroke-dasharray="2 3"/>`;
    const lx = cx + (R + 40) * Math.cos(a), ly = cy + (R + 40) * Math.sin(a);
    const anchor = Math.abs(Math.cos(a)) < 0.2 ? "middle" : Math.cos(a) > 0 ? "start" : "end";
    labels += `<text x="${lx}" y="${ly}" class="risk-radar-label" text-anchor="${anchor}" dominant-baseline="middle">${escapeHtml(c.name.split(" ")[0])}</text>`;
    const ratio = c.score / 100;
    const px = cx + R * ratio * Math.cos(a), py = cy + R * ratio * Math.sin(a);
    pts.push(`${px},${py}`);
    const bandColor = `var(--${riskBandKey(riskBandOf(c.score)) === "low" ? "ok" : riskBandKey(riskBandOf(c.score)) === "medium" ? "warn" : "crit"})`;
    dots += `<circle cx="${px}" cy="${py}" r="4" fill="${bandColor}"/>`;
    const sx = cx + (R * ratio + 16) * Math.cos(a), sy = cy + (R * ratio + 16) * Math.sin(a);
    dots += `<text x="${sx}" y="${sy}" class="risk-radar-score" text-anchor="${anchor}" dominant-baseline="middle" fill="${bandColor}">${c.score}</text>`;
  });
  const poly = `<polygon points="${pts.join(" ")}" fill="var(--accent)" fill-opacity="0.22" stroke="var(--accent)" stroke-width="2.5"/>`;
  return `<svg class="risk-radar" viewBox="0 0 400 340">${axes}${poly}${dots}${labels}</svg>`;
}

// idPrefix — общая часть id элементов на странице ("ad" / "net"), ожидает
// разметку: #{idPrefix}-report-fleet(-body), #{idPrefix}-report-domain(-body),
// #{idPrefix}-report-meta, #{idPrefix}-report-refresh, #{idPrefix}-domain-back.
// fetchReport — async () => отчёт или null при ошибке.
// rowLabel — заголовок строки списка ("Домен"/"Устройство").
// itemsKey — ключ массива объектов в отчёте ("domains"/"devices").
function createRiskReportPanel(idPrefix, fetchReport, rowLabel, itemsKey, emptyMessage) {
  let report = null;
  let sortedItems = [];

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
    sortedItems = (report[itemsKey] || [])
      .slice()
      .sort((a, b) => naturalCompare(a.label || a.id, b.label || b.id));

    const generated = new Date(report.generated_at).toLocaleString("ru-RU");
    const rowLabelLower = rowLabel === "Домен" ? "доменов" : "устройств";
    let metaText = `Сформирован: ${generated} · ${rowLabelLower} в отчёте: ${sortedItems.length} · каталог правил v${report.catalog_version} (${report.catalog_updated_at})`;
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
    if (sortedItems.length === 0) {
      body.innerHTML = `<div class="empty">${emptyMessage || "Нет данных для отчёта"}</div>`;
      return;
    }
    body.innerHTML = sortedItems
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
    const d = sortedItems[i];
    if (!d) return;

    let tiles = "";
    d.categories.forEach((c) => {
      const failCount = c.rules.filter((r) => r.points > 0).length;
      tiles += `<div class="risk-tile">
        <div class="t-title">${escapeHtml(c.name)}</div>
        <div class="t-score risk-band ${riskBandKey(riskBandOf(c.score))}" style="display:inline-block">${c.score} / 100</div>
        <div class="t-sub">${failCount} нарушени${failCount === 1 ? "е" : failCount >= 2 && failCount <= 4 ? "я" : "й"}</div>
      </div>`;
    });

    let sections = "";
    d.categories.forEach((c) => {
      const rules = c.rules.slice().sort((a, b) => b.points - a.points);
      let ruleRows = "";
      rules.forEach((r) => {
        const objectsBlock = (r.objects || []).length
          ? `<details class="risk-details" open><summary>Затронуто: ${r.objects.length}</summary><div class="risk-objects">${r.objects.map((o) => `<div>${escapeHtml(o)}</div>`).join("")}</div></details>`
          : "";
        const fixBlock = r.points > 0 && r.fix
          ? `<details class="risk-details"><summary>Как исправить</summary><div class="risk-fix">${escapeHtml(r.fix)}</div></details>`
          : "";
        ruleRows += `<tr>
          <td class="risk-pts" style="color:${r.points > 0 ? "var(--crit)" : "var(--ok)"}">${r.points}</td>
          <td>
            <div class="name">${escapeHtml(r.name)}</div>
            <div class="desc">${escapeHtml(r.description)}</div>
            ${objectsBlock}
            ${fixBlock}
          </td>
        </tr>`;
      });
      sections += `<div class="risk-cat-section">
        <div class="risk-cat-head">
          <span>${escapeHtml(c.name)}</span>
          <span class="risk-band ${riskBandKey(riskBandOf(c.score))}">${c.score} / 100</span>
        </div>
        <table class="risk-rules-table"><thead><tr><th>Баллы</th><th>Правило</th></tr></thead><tbody>${ruleRows}</tbody></table>
      </div>`;
    });

    el("report-domain-body").innerHTML = `
      <div class="risk-sticky-head">
        <div class="risk-dev-title-row">
          <div>
            <div style="font-weight:600;font-size:15px">${escapeHtml(d.label || d.id)}</div>
            <div class="sub" style="color:var(--text-dim);font-family:var(--mono);font-size:11.5px">${escapeHtml(d.domain || `${d.vendor ? d.vendor + " · " : ""}${d.address || ""}${d.scanned_at ? " · бэкап от " + new Date(d.scanned_at).toLocaleString("ru-RU") : ""}`)}</div>
          </div>
          <div class="risk-overall risk-band ${riskBandKey(d.risk_band)}">${d.risk_score} <span class="risk-overall-sub">риск / 100 · ${escapeHtml(d.risk_band)}</span></div>
        </div>
        <div class="risk-tiles">${tiles}</div>
      </div>
      ${riskRadarSvg(d.categories)}
      ${sections}
    `;
    el("report-fleet").hidden = true;
    el("report-domain").hidden = false;
  }

  el("report-refresh").addEventListener("click", load);
  el("domain-back").addEventListener("click", () => {
    el("report-domain").hidden = true;
    el("report-fleet").hidden = false;
  });

  return { load, rowLabel };
}
