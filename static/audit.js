// Аудит конфигураций — правила + прогон на выбранном узле.

async function refreshRules() {
  const body = document.getElementById("rules-body");
  let rules;
  try {
    rules = await api("/api/audit-rules");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("rules-count").textContent = rules.length;
  if (rules.length === 0) {
    body.innerHTML = `<div class="empty">Правил нет — добавь ниже</div>`;
    return;
  }
  body.innerHTML = rules
    .map(
      (r) => `
      <div class="channel-row">
        <span>
          <span class="sev-dot ${r.severity}" style="display:inline-block"></span>
          ${escapeHtml(r.name)}
          <span class="count">· ${r.kind === "must_contain" ? "должно быть" : "не должно быть"} «${escapeHtml(r.pattern)}»${r.vendor ? " · " + escapeHtml(r.vendor) : ""}</span>
        </span>
        <button data-id="${r.id}" class="del-rule">удалить</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".del-rule").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/audit-rules/${btn.dataset.id}`, { method: "DELETE" });
        toast("Правило удалено");
        refreshRules();
        loadCompliance();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-rule").addEventListener("click", async () => {
  const name = document.getElementById("r-name").value.trim();
  const pattern = document.getElementById("r-pattern").value.trim();
  const description = document.getElementById("r-desc").value.trim();
  if (!name || !pattern || !description) return toast("Заполни имя, строку и описание", true);
  try {
    await api("/api/audit-rules", {
      method: "POST",
      body: JSON.stringify({
        name,
        kind: document.getElementById("r-kind").value,
        pattern,
        vendor: document.getElementById("r-vendor").value || null,
        severity: document.getElementById("r-severity").value,
        description,
      }),
    });
    document.getElementById("r-name").value = "";
    document.getElementById("r-pattern").value = "";
    document.getElementById("r-desc").value = "";
    toast("Правило добавлено");
    refreshRules();
    loadCompliance();
  } catch (e) {
    toast(e.message, true);
  }
});

async function loadNodePicker() {
  const select = document.getElementById("audit-node-select");
  try {
    const nodes = sortNodesNatural(await api("/api/nodes"));
    select.innerHTML = `<option value="">выбери узел…</option>` + nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
}

function renderFindings(findings) {
  document.getElementById("findings-count").textContent = findings.length;
  const body = document.getElementById("findings-body");
  if (findings.length === 0) {
    body.innerHTML = `<div class="empty">Находок нет</div>`;
    return;
  }
  body.innerHTML = findings
    .map(
      (f) => `
      <div class="incident-row">
        <span class="sev-dot ${f.ok ? "" : f.severity}" style="background:${f.ok ? "var(--ok)" : ""}"></span>
        <div class="main">
          <div class="label">${escapeHtml(f.rule_name)} ${f.ok ? "— ok" : "— находка"}</div>
          <div class="detail">${escapeHtml(f.detail)}</div>
        </div>
      </div>`
    )
    .join("");
}

document.getElementById("run-audit").addEventListener("click", async () => {
  const nodeId = document.getElementById("audit-node-select").value;
  if (!nodeId) return toast("Выбери узел", true);
  try {
    const findings = await api(`/api/nodes/${nodeId}/audit`, { method: "POST" });
    renderFindings(findings);
    const bad = findings.filter((f) => !f.ok).length;
    toast(bad === 0 ? "Аудит чист" : `Аудит: ${bad} находок`, bad > 0);
  } catch (e) {
    toast(e.message, true);
  }
});

document.getElementById("audit-node-select").addEventListener("change", async (ev) => {
  if (!ev.target.value) return;
  try {
    const findings = await api(`/api/nodes/${ev.target.value}/audit`);
    renderFindings(findings);
  } catch (e) {
    /* нет прав/данных — оставим форму как есть */
  }
});

async function loadCompliance() {
  const body = document.getElementById("compliance-body");
  let data;
  try {
    data = await api("/api/reports/compliance");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  const rules = data.rules || [];
  if (rules.length === 0) {
    body.innerHTML = `<div class="empty">Правил нет — добавь их выше</div>`;
    return;
  }
  body.innerHTML = rules
    .map((r) => {
      const clean = r.non_compliant.length === 0;
      const listBlock = clean
        ? ""
        : `<details class="risk-details" open><summary>Не соответствует: ${r.non_compliant.length}</summary><div class="risk-objects">${r.non_compliant
            .map((n) => `<div>${escapeHtml(n.hostname)} — ${escapeHtml(n.detail)}</div>`)
            .join("")}</div></details>`;
      return `<div class="incident-row" style="align-items:flex-start">
        <span class="sev-dot ${clean ? "" : r.severity}" style="background:${clean ? "var(--ok)" : ""};margin-top:6px"></span>
        <div class="main">
          <div class="label">${escapeHtml(r.name)} <span class="count">· проверено: ${r.checked_count} · ${clean ? "все соответствуют" : r.non_compliant.length + " не соответствуют"}</span></div>
          <div class="detail">${escapeHtml(r.description)}</div>
          ${listBlock}
        </div>
      </div>`;
    })
    .join("");
}

document.getElementById("compliance-refresh").addEventListener("click", loadCompliance);

function onKeySaved() {
  refreshRules();
  loadNodePicker();
  loadCompliance();
}

refreshRules();
loadNodePicker();
loadCompliance();
