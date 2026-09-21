// Централизованные учётки для подключения к узлам — на конкретный узел,
// на группу, на вендор, или "по умолчанию". См. Credential в models.py
// и credentials_engine.resolve_credential (порядок поиска: узел ->
// группа -> вендор -> по умолчанию).

// Вендор — по прямому запросу пользователя (2026-09-21): сетевые группы
// здесь смешанные (в одной группе и cisco_ios, и junos), логин реально
// зависит от вендора устройства, не от того, в какую сетевую группу оно
// попало.
const VENDOR_LABELS = {
  cisco_ios: "Cisco IOS",
  cisco_ios_telnet: "Cisco IOS (Telnet)",
  junos: "Juniper Junos",
  generic: "прочее оборудование",
};

async function refreshScopeOptions() {
  let groups = [];
  let nodes = [];
  try {
    [groups, nodes] = await Promise.all([api("/api/groups"), api("/api/nodes")]);
  } catch (e) {
    return;
  }
  nodes = sortNodesNatural(nodes);
  const groupOptions = groups.map((g) => `<option value="group:${g.id}">${escapeHtml(g.name)}</option>`).join("");
  const nodeOptions = nodes.map((n) => `<option value="node:${n.id}">${escapeHtml(n.name)}</option>`).join("");
  const vendorOptions = Object.entries(VENDOR_LABELS)
    .map(([key, label]) => `<option value="vendor:${key}">${escapeHtml(label)}</option>`)
    .join("");
  document.getElementById("new-cred-scope").innerHTML =
    `<option value="default">по умолчанию</option>` +
    `<optgroup label="Вендоры (применяется на всём оборудовании этого вендора, независимо от группы)">${vendorOptions}</optgroup>` +
    (groupOptions ? `<optgroup label="Группы">${groupOptions}</optgroup>` : "") +
    (nodeOptions ? `<optgroup label="Узлы (зоопарк — своя учётка на коммутатор)">${nodeOptions}</optgroup>` : "");
}

async function refreshCredentials() {
  const body = document.getElementById("cred-body");
  let creds;
  try {
    creds = await api("/api/credentials");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("cred-count").textContent = creds.length;

  if (creds.length === 0) {
    body.innerHTML = `<div class="empty">Учёток ещё нет — заведи ниже</div>`;
    return;
  }

  body.innerHTML = creds
    .map((c) => {
      const scope = c.node_id
        ? `узел: ${escapeHtml(c.node_name || `#${c.node_id}`)}`
        : c.group_id
        ? `группа: ${escapeHtml(c.group_name || `#${c.group_id}`)}`
        : c.vendor
        ? `вендор: ${escapeHtml(VENDOR_LABELS[c.vendor] || c.vendor)}`
        : "по умолчанию";
      const secret = c.has_password ? "пароль ••••" : c.key_path ? `ключ: ${escapeHtml(c.key_path)}` : "нет пароля/ключа — подключение не пройдёт";
      const label = c.label ? `${escapeHtml(c.label)} · ` : "";
      return `
      <div class="channel-row">
        <span>${label}<b>${escapeHtml(c.username)}</b> · ${scope} · ${secret}</span>
        <button data-id="${c.id}" data-scope="${scope}" class="del-cred">удалить</button>
      </div>`;
    })
    .join("");

  body.querySelectorAll(".del-cred").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить учётку (${btn.dataset.scope})? Затронутые узлы снова будут спрашивать логин.`)) return;
      try {
        await api(`/api/credentials/${btn.dataset.id}`, { method: "DELETE" });
        toast("Учётка удалена");
        refreshCredentials();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-cred").addEventListener("click", async () => {
  const scopeValue = document.getElementById("new-cred-scope").value;
  const label = document.getElementById("new-cred-label").value.trim();
  const username = document.getElementById("new-cred-username").value.trim();
  const password = document.getElementById("new-cred-password").value;
  const keyPath = document.getElementById("new-cred-keypath").value.trim();
  if (!username) return toast("Нужен логин", true);
  if (!password && !keyPath) return toast("Укажи пароль или путь к ключу", true);

  let groupId = null;
  let nodeId = null;
  let vendor = null;
  if (scopeValue.startsWith("group:")) groupId = Number(scopeValue.slice(6));
  else if (scopeValue.startsWith("node:")) nodeId = Number(scopeValue.slice(5));
  else if (scopeValue.startsWith("vendor:")) vendor = scopeValue.slice(7);

  try {
    await api("/api/credentials", {
      method: "POST",
      body: JSON.stringify({
        group_id: groupId,
        node_id: nodeId,
        vendor,
        label,
        username,
        password: password || null,
        key_path: keyPath || null,
      }),
    });
    document.getElementById("new-cred-label").value = "";
    document.getElementById("new-cred-username").value = "";
    document.getElementById("new-cred-password").value = "";
    document.getElementById("new-cred-keypath").value = "";
    toast("Учётка сохранена");
    refreshCredentials();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshScopeOptions();
  refreshCredentials();
}

refreshScopeOptions();
refreshCredentials();
