// Пользователи веб-интерфейса — логин/пароль, роль, область по группе.

let _groupsById = {};

// Пункт 3 запроса пользователя (2026-09-25: "разработать выбирать кто с
// чем будет работать") — чек-лист разделов сайта строится из того же
// NAV_GROUPS, что и сама навигация (common.js), не дублируется здесь
// отдельным списком: появится новый раздел в меню — появится и в
// чек-листе сам собой.
function renderPageChecklist(containerId, checkedPages) {
  const container = document.getElementById(containerId);
  const checked = new Set(checkedPages || []);
  container.innerHTML = NAV_GROUPS.map((group) => {
    const title = group.title || "Дашборд";
    const items = group.items
      .map(
        (item) => `
        <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;padding:3px 0;">
          <input type="checkbox" value="${item.href}" ${checked.has(item.href) ? "checked" : ""}> ${escapeHtml(item.label)}
        </label>`
      )
      .join("");
    return `<div style="padding:8px 16px;border-bottom:1px solid var(--border);">
      <div style="font-size:11px;text-transform:uppercase;color:var(--text-dim);letter-spacing:.05em;margin-bottom:4px;">${escapeHtml(title)}</div>
      ${items}
    </div>`;
  }).join("");
}

function readPageChecklist(containerId) {
  return [...document.querySelectorAll(`#${containerId} input[type="checkbox"]:checked`)].map((el) => el.value);
}

async function refreshGroupOptions() {
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  _groupsById = Object.fromEntries(groups.map((g) => [g.id, g.name]));
  document.getElementById("new-user-group").innerHTML =
    `<option value="">все группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  document.getElementById("new-key-group").innerHTML =
    `<option value="">все группы</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
}

async function refreshUsers() {
  const body = document.getElementById("users-body");
  let users;
  try {
    users = await api("/api/users");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("users-count").textContent = users.length;

  body.innerHTML = users
    .map((u) => {
      const scope = u.group_id ? `группа: ${escapeHtml(_groupsById[u.group_id] || `#${u.group_id}`)}` : "все группы";
      const lastLogin = u.last_login_at ? timeAgo(u.last_login_at) : "ни разу";
      const inactive = u.active ? "" : ` · <span style="color:var(--crit)">отключён</span>`;
      // Источник важен: у доменной учётки пароль в AD, менять его здесь нечем.
      const source = u.source === "ad" ? " · из AD" : "";
      const pending = u.must_change_password
        ? ` · <span style="color:var(--warn)">ждёт смены пароля</span>`
        : "";
      const pagesNote = u.allowed_pages ? ` · разделов: ${u.allowed_pages.length}` : "";
      return `
      <div class="channel-row">
        <span><b>${escapeHtml(u.username)}</b>${source} · ${escapeHtml(u.role)} · ${scope} · вход: ${escapeHtml(lastLogin)}${inactive}${pending}${pagesNote}</span>
        <span style="display:flex;gap:6px;">
          <button data-id="${u.id}" class="edit-pages-toggle">разделы</button>
          <button data-id="${u.id}" data-name="${escapeHtml(u.username)}" class="del-user">удалить</button>
        </span>
      </div>
      <div id="edit-pages-${u.id}" hidden style="padding:0 16px 10px;border-bottom:1px solid var(--border);"></div>`;
    })
    .join("");

  // Доменные учётки сюда не попадают: их пароль меняется в AD.
  document.getElementById("pw-user").innerHTML = users
    .filter((u) => u.source !== "ad")
    .map((u) => `<option value="${u.id}">${escapeHtml(u.username)}</option>`)
    .join("");

  body.querySelectorAll(".del-user").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить пользователя «${btn.dataset.name}»? Его открытые сессии закроются.`)) return;
      try {
        await api(`/api/users/${btn.dataset.id}`, { method: "DELETE" });
        toast("Пользователь удалён");
        refreshUsers();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });

  body.querySelectorAll(".edit-pages-toggle").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.id;
      const box = document.getElementById(`edit-pages-${id}`);
      const wasHidden = box.hidden;
      box.hidden = !wasHidden;
      if (!wasHidden) return; // сворачиваем — содержимое можно оставить как есть
      const u = users.find((x) => String(x.id) === id);
      const listId = `edit-pages-list-${id}`;
      box.innerHTML =
        `<label style="display:flex;align-items:center;gap:6px;font-size:12.5px;padding:8px 0 4px;">` +
        `<input type="checkbox" id="edit-restrict-${id}" ${u.allowed_pages ? "checked" : ""}> ограничить разделы (иначе видит все)</label>` +
        `<div id="${listId}" ${u.allowed_pages ? "" : "hidden"}></div>` +
        `<button id="edit-pages-save-${id}" style="margin-top:6px;">Сохранить</button>`;
      renderPageChecklist(listId, u.allowed_pages);
      document.getElementById(`edit-restrict-${id}`).addEventListener("change", (ev) => {
        document.getElementById(listId).hidden = !ev.target.checked;
      });
      document.getElementById(`edit-pages-save-${id}`).addEventListener("click", async () => {
        const restrict = document.getElementById(`edit-restrict-${id}`).checked;
        const pages = restrict ? readPageChecklist(listId) : null;
        if (restrict && pages.length === 0) return toast("Отметь хотя бы один раздел", true);
        try {
          await api(`/api/users/${id}`, { method: "PATCH", body: JSON.stringify({ allowed_pages: pages }) });
          toast("Разделы сохранены");
          refreshUsers();
        } catch (e) {
          toast(e.message, true);
        }
      });
    });
  });
}

document.getElementById("new-user-restrict-pages").addEventListener("change", (ev) => {
  const box = document.getElementById("new-user-pages");
  box.hidden = !ev.target.checked;
  if (ev.target.checked) renderPageChecklist("new-user-pages", null);
});

document.getElementById("add-user").addEventListener("click", async () => {
  const username = document.getElementById("new-user-name").value.trim();
  const password = document.getElementById("new-user-password").value;
  const groupValue = document.getElementById("new-user-group").value;
  if (!username || !password) return toast("Нужны логин и пароль", true);
  const restrictPages = document.getElementById("new-user-restrict-pages").checked;
  const allowedPages = restrictPages ? readPageChecklist("new-user-pages") : null;
  if (restrictPages && allowedPages.length === 0) return toast("Отметь хотя бы один раздел", true);
  try {
    await api("/api/users", {
      method: "POST",
      body: JSON.stringify({
        username,
        password,
        role: document.getElementById("new-user-role").value,
        group_id: groupValue ? Number(groupValue) : null,
        allowed_pages: allowedPages,
      }),
    });
    document.getElementById("new-user-name").value = "";
    document.getElementById("new-user-password").value = "";
    document.getElementById("new-user-restrict-pages").checked = false;
    document.getElementById("new-user-pages").hidden = true;
    toast("Пользователь создан");
    refreshUsers();
  } catch (e) {
    toast(e.message, true);
  }
});

document.getElementById("change-password").addEventListener("click", async () => {
  const userId = document.getElementById("pw-user").value;
  const password = document.getElementById("pw-password").value;
  if (!userId || !password) return toast("Выбери пользователя и введи пароль", true);
  try {
    const result = await api(`/api/users/${userId}/password`, {
      method: "POST",
      body: JSON.stringify({ password }),
    });
    document.getElementById("pw-password").value = "";
    toast(`Пароль изменён, закрыто сессий: ${result.sessions_closed}`);
    // Баннер про пароль по умолчанию мог висеть — после смены он неактуален.
    const banner = document.getElementById("default-password-warning");
    if (banner) banner.remove();
  } catch (e) {
    toast(e.message, true);
  }
});

// API-ключи (запрос пользователя, 2026-09-25: "чтобы я сам выдавал
// API-ключи для пользователей") — раньше POST/GET/revoke /api/api-keys
// уже существовали в бэкенде, но интерфейса для них не было вообще,
// заводить ключ можно было только curl'ом напрямую.
async function refreshApiKeys() {
  const body = document.getElementById("apikeys-body");
  let keys;
  try {
    keys = await api("/api/api-keys");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("apikeys-count").textContent = keys.length;

  if (keys.length === 0) {
    body.innerHTML = `<div class="empty">Ключей пока нет — выдай ниже</div>`;
    return;
  }
  body.innerHTML = keys
    .map((k) => {
      const scope = k.group_id ? `группа: ${escapeHtml(_groupsById[k.group_id] || `#${k.group_id}`)}` : "все группы";
      const revoked = k.revoked ? ` · <span style="color:var(--crit)">отозван</span>` : "";
      return `
      <div class="channel-row">
        <span><b>${escapeHtml(k.label)}</b> · ${escapeHtml(k.role)} · ${scope} · выдан ${escapeHtml(timeAgo(k.created_at))}${revoked}</span>
        ${k.revoked ? "" : `<button data-id="${k.id}" data-name="${escapeHtml(k.label)}" class="revoke-key">отозвать</button>`}
      </div>`;
    })
    .join("");

  body.querySelectorAll(".revoke-key").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Отозвать ключ «${btn.dataset.name}»? Программа, которая им пользуется, перестанет иметь доступ.`)) return;
      try {
        await api(`/api/api-keys/${btn.dataset.id}/revoke`, { method: "POST" });
        toast("Ключ отозван");
        refreshApiKeys();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-key").addEventListener("click", async () => {
  const label = document.getElementById("new-key-label").value.trim();
  const groupValue = document.getElementById("new-key-group").value;
  if (!label) return toast("Укажи метку ключа", true);
  const resultBox = document.getElementById("new-key-result");
  try {
    const result = await api("/api/api-keys", {
      method: "POST",
      body: JSON.stringify({
        label,
        role: document.getElementById("new-key-role").value,
        group_id: groupValue ? Number(groupValue) : null,
      }),
    });
    document.getElementById("new-key-label").value = "";
    resultBox.style.display = "";
    resultBox.innerHTML =
      `<div style="color:var(--warn);margin-bottom:6px;">Скопируй сейчас — второй раз этот ключ не покажется:</div>` +
      `<code style="font-family:var(--mono);font-size:13px;user-select:all;background:var(--surface-2);padding:6px 10px;border-radius:6px;display:inline-block;">${escapeHtml(result.key)}</code>`;
    toast("Ключ создан");
    refreshApiKeys();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshGroupOptions();
  refreshUsers();
  refreshApiKeys();
}

refreshGroupOptions();
refreshUsers();
refreshApiKeys();
