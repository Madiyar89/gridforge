// LDAP-подключения для AD-аудита — несколько доменов сразу, пароль
// хранится зашифрованным. См. LdapConnection в models.py.

async function refreshLdapConnections() {
  const body = document.getElementById("ldap-body");
  let conns;
  try {
    conns = await api("/api/ldap-connections");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("ldap-count").textContent = conns.length;

  if (conns.length === 0) {
    body.innerHTML = `<div class="empty">Подключений ещё нет — заведи ниже</div>`;
    return;
  }

  body.innerHTML = conns
    .map(
      (c) => `
      <div class="channel-row">
        <span>
          <b>${escapeHtml(c.label)}</b> · ${escapeHtml(c.dc_host)}:${c.port}${c.use_ssl ? " (LDAPS)" : ""}
          <br><span class="addr">${escapeHtml(c.username)}@${escapeHtml(c.domain)} · ${escapeHtml(c.base_dn)}</span>
        </span>
        <button data-id="${c.id}" data-label="${escapeHtml(c.label)}" class="del-ldap">удалить</button>
      </div>`
    )
    .join("");

  body.querySelectorAll(".del-ldap").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить подключение «${btn.dataset.label}»?`)) return;
      try {
        await api(`/api/ldap-connections/${btn.dataset.id}`, { method: "DELETE" });
        toast("Подключение удалено");
        refreshLdapConnections();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-ldap").addEventListener("click", async () => {
  const label = document.getElementById("new-ldap-label").value.trim();
  const dc_host = document.getElementById("new-ldap-host").value.trim();
  const port = Number(document.getElementById("new-ldap-port").value) || 636;
  const domain = document.getElementById("new-ldap-domain").value.trim();
  const base_dn = document.getElementById("new-ldap-basedn").value.trim();
  const username = document.getElementById("new-ldap-username").value.trim();
  const password = document.getElementById("new-ldap-password").value;
  const use_ssl = document.getElementById("new-ldap-ssl").checked;

  if (!label || !dc_host || !domain || !base_dn || !username || !password) {
    return toast("Заполни все поля", true);
  }

  const btn = document.getElementById("add-ldap");
  btn.disabled = true;
  btn.textContent = "Проверяю…";
  try {
    await api("/api/ldap-connections", {
      method: "POST",
      body: JSON.stringify({ label, dc_host, port, domain, base_dn, username, password, use_ssl }),
    });
    ["label", "host", "domain", "basedn", "username", "password"].forEach((id) => {
      document.getElementById(`new-ldap-${id}`).value = "";
    });
    document.getElementById("new-ldap-port").value = 636;
    toast("Подключение сохранено");
    refreshLdapConnections();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Сохранить";
  }
});

function onKeySaved() {
  refreshLdapConnections();
}

refreshLdapConnections();
