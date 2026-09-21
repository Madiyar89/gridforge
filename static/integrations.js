// Интеграции с внешними системами (Graylog, Zabbix) — URL + токен,
// список ключей фиксирован на бэкенде (INTEGRATION_REGISTRY,
// integrations_engine.py), здесь только рендер и форма.

let _integrations = [];
let _openKey = null;

async function refreshIntegrations() {
  const body = document.getElementById("integrations-body");
  try {
    _integrations = await api("/api/integrations");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }

  body.innerHTML = _integrations
    .map(
      (i) => `
    <div class="integration-card" data-key="${i.key}">
      <div class="integration-head">
        <span><b>${escapeHtml(i.label)}</b>${i.configured ? ` <span class="addr">${escapeHtml(i.url)}</span>` : ""}</span>
        <span>
          <span class="integration-status ${i.configured ? "ok" : "off"}">${i.configured ? "настроено" : "не настроено"}</span>
          <button type="button" class="btn-ghost toggle-form" data-key="${i.key}">${i.configured ? "изменить" : "настроить"}</button>
          ${i.configured ? `<button type="button" class="btn-ghost remove-integration" data-key="${i.key}">отключить</button>` : ""}
        </span>
      </div>
      <div class="integration-form" id="form-${i.key}">
        <input type="text" id="url-${i.key}" placeholder="${escapeHtml(i.url_placeholder)}">
        <input type="password" id="token-${i.key}" placeholder="API-токен">
        <button type="button" class="save-integration" data-key="${i.key}">Сохранить</button>
      </div>
    </div>`
    )
    .join("");

  body.querySelectorAll(".toggle-form").forEach((btn) => {
    btn.addEventListener("click", () => toggleForm(btn.dataset.key));
  });
  body.querySelectorAll(".save-integration").forEach((btn) => {
    btn.addEventListener("click", () => saveIntegration(btn.dataset.key));
  });
  body.querySelectorAll(".remove-integration").forEach((btn) => {
    btn.addEventListener("click", () => removeIntegration(btn.dataset.key));
  });

  if (_openKey) {
    const form = document.getElementById(`form-${_openKey}`);
    if (form) form.classList.add("open");
  }
}

function toggleForm(key) {
  const form = document.getElementById(`form-${key}`);
  const isOpen = form.classList.contains("open");
  document.querySelectorAll(".integration-form").forEach((f) => f.classList.remove("open"));
  _openKey = isOpen ? null : key;
  if (!isOpen) form.classList.add("open");
}

async function saveIntegration(key) {
  const url = document.getElementById(`url-${key}`).value.trim();
  const token = document.getElementById(`token-${key}`).value;
  if (!url || !token) return toast("Укажи URL и токен", true);

  try {
    await api(`/api/integrations/${key}`, {
      method: "PUT",
      body: JSON.stringify({ url, api_token: token }),
    });
    toast("Настройки сохранены");
    _openKey = null;
    refreshIntegrations();
  } catch (e) {
    toast(e.message, true);
  }
}

async function removeIntegration(key) {
  const i = _integrations.find((x) => x.key === key);
  if (!confirm(`Отключить интеграцию с ${i.label}? URL и токен будут удалены с сервера.`)) return;
  try {
    await api(`/api/integrations/${key}`, { method: "DELETE" });
    toast("Интеграция отключена");
    refreshIntegrations();
  } catch (e) {
    toast(e.message, true);
  }
}

function onKeySaved() {
  refreshIntegrations();
}

refreshIntegrations();
