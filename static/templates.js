// Шаблоны мониторинга — список, создание (JSON probe_defs), применение к узлу.

async function refreshTemplates() {
  const body = document.getElementById("templates-body");
  let templates;
  try {
    templates = await api("/api/templates");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("templates-count").textContent = templates.length;
  if (templates.length === 0) {
    body.innerHTML = `<div class="empty">Шаблонов нет — добавь ниже</div>`;
    return;
  }
  body.innerHTML = templates
    .map(
      (t) => `
      <div class="template-row">
        <span>${escapeHtml(t.name)} ${t.vendor ? `<span class="vendor">${escapeHtml(t.vendor)}</span>` : ""} <span class="count">· ${t.probe_count} проверок</span></span>
        <span class="actions">
          <button data-id="${t.id}" data-name="${escapeHtml(t.name)}" class="apply-tpl">применить</button>
          <button data-id="${t.id}" class="del-tpl">удалить</button>
        </span>
      </div>`
    )
    .join("");
  body.querySelectorAll(".del-tpl").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/templates/${btn.dataset.id}`, { method: "DELETE" });
        toast("Шаблон удалён");
        refreshTemplates();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
  body.querySelectorAll(".apply-tpl").forEach((btn) => {
    btn.addEventListener("click", () => openApplyModal(btn.dataset.id, btn.dataset.name));
  });
}

document.getElementById("add-template").addEventListener("click", async () => {
  const name = document.getElementById("new-tpl-name").value.trim();
  const vendor = document.getElementById("new-tpl-vendor").value;
  const defsRaw = document.getElementById("new-tpl-defs").value.trim();
  if (!name || !defsRaw) return toast("Укажи имя и probe_defs", true);
  let probe_defs;
  try {
    probe_defs = JSON.parse(defsRaw);
  } catch (e) {
    return toast("probe_defs — невалидный JSON: " + e.message, true);
  }
  try {
    await api("/api/templates", {
      method: "POST",
      body: JSON.stringify({ name, vendor: vendor || null, probe_defs }),
    });
    document.getElementById("new-tpl-name").value = "";
    document.getElementById("new-tpl-defs").value = "";
    toast("Шаблон добавлен");
    refreshTemplates();
  } catch (e) {
    toast(e.message, true);
  }
});

// --- Модалка "Применить к узлу" ---

const applyModal = document.getElementById("apply-modal");
const applyForm = document.getElementById("apply-form");
let applyModalTplId = null;

async function openApplyModal(tplId, tplName) {
  applyModalTplId = tplId;
  document.getElementById("apply-modal-tpl").textContent = tplName;
  const select = document.getElementById("apply-node");
  select.innerHTML = `<option>загрузка…</option>`;
  try {
    const nodes = await api("/api/nodes");
    select.innerHTML = nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)} (${escapeHtml(n.address)})</option>`).join("");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
  applyModal.showModal();
}

document.getElementById("apply-cancel").addEventListener("click", () => applyModal.close());

applyForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const nodeId = Number(document.getElementById("apply-node").value);
  if (!nodeId) return toast("Выбери узел", true);
  try {
    const result = await api(`/api/templates/${applyModalTplId}/apply`, {
      method: "POST",
      body: JSON.stringify({ node_id: nodeId }),
    });
    applyModal.close();
    toast(`Применено: ${result.probe_ids.length} проверок, ${result.watch_ids.length} условий`);
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshTemplates();
}

refreshTemplates();
setInterval(refreshTemplates, REFRESH_MS);
