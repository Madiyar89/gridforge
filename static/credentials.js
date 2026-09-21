// Централизованные учётки для подключения к узлам — по группе или "по
// умолчанию" (без группы). См. Credential в models.py и
// credentials_engine.resolve_credential.

let _groupsById = {};

async function refreshGroupOptions() {
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  _groupsById = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  document.getElementById("new-cred-group").innerHTML =
    `<option value="">по умолчанию (без группы)</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
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
      const scope = c.group_id ? `группа: ${escapeHtml(c.group_name || `#${c.group_id}`)}` : "по умолчанию";
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
      if (!confirm(`Удалить учётку (${btn.dataset.scope})? Узлы этой группы снова будут спрашивать логин.`)) return;
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
  const groupValue = document.getElementById("new-cred-group").value;
  const label = document.getElementById("new-cred-label").value.trim();
  const username = document.getElementById("new-cred-username").value.trim();
  const password = document.getElementById("new-cred-password").value;
  const keyPath = document.getElementById("new-cred-keypath").value.trim();
  if (!username) return toast("Нужен логин", true);
  if (!password && !keyPath) return toast("Укажи пароль или путь к ключу", true);
  try {
    await api("/api/credentials", {
      method: "POST",
      body: JSON.stringify({
        group_id: groupValue ? Number(groupValue) : null,
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
  refreshGroupOptions();
  refreshCredentials();
}

refreshGroupOptions();
refreshCredentials();
