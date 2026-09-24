// Бэкапы конфигураций — выбор узла, снятие снимка, история, diff.
// Плюс групповой бэкап (по запросу пользователя, 2026-09-24) — та же
// логика "группа -> цикл по узлам", что уже в ports.js/vuln.js.

let selectedNodeId = null;

async function loadNodePicker() {
  const select = document.getElementById("backup-node-select");
  try {
    const nodes = sortNodesNatural(await api("/api/nodes"));
    select.innerHTML = `<option value="">выбери узел…</option>` + nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)} (${escapeHtml(n.address)})</option>`).join("");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
}

async function loadGroupPicker() {
  const select = document.getElementById("backup-group-select");
  try {
    const groups = await api("/api/groups");
    select.innerHTML =
      `<option value="">выбери группу…</option>` +
      groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)} (${g.node_count} узел(ов))</option>`).join("");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
}

document.getElementById("run-group-backup").addEventListener("click", async () => {
  const groupId = document.getElementById("backup-group-select").value;
  const command = document.getElementById("bg-cmd").value.trim();
  if (!groupId) return toast("Выбери группу", true);
  if (!command) return toast("Укажи команду (например: show running-config)", true);

  const status = document.getElementById("group-backup-status");
  const btn = document.getElementById("run-group-backup");
  let nodes;
  try {
    nodes = await api(`/api/nodes?group_id=${groupId}`);
  } catch (e) {
    return toast(e.message, true);
  }
  if (nodes.length === 0) return toast("В этой группе узлов нет", true);

  btn.disabled = true;
  let ok = 0;
  let changed = 0;
  let failed = 0;
  for (let i = 0; i < nodes.length; i++) {
    const n = nodes[i];
    status.textContent = `${i + 1}/${nodes.length} — ${n.name}…`;
    try {
      const result = await apiWithCredentials(`/api/nodes/${n.id}/backup`, {
        method: "POST",
        body: JSON.stringify({ username: null, command, key_path: null, port: 22 }),
      });
      if (result.error) failed++;
      else {
        ok++;
        if (result.changed) changed++;
      }
    } catch (e) {
      failed++;
    }
  }
  btn.disabled = false;
  status.textContent = `готово: снято ${ok}, изменилось ${changed}, ошибок ${failed}`;
  toast(`Групповой бэкап завершён: снято ${ok}, изменилось ${changed}, ошибок ${failed}`, failed > 0 && ok === 0);
  if (selectedNodeId && nodes.some((n) => String(n.id) === String(selectedNodeId))) refreshBackups();
});

document.getElementById("backup-node-select").addEventListener("change", (ev) => {
  selectedNodeId = ev.target.value || null;
  document.getElementById("backup-panels").hidden = !selectedNodeId;
  if (selectedNodeId) refreshBackups();
});

async function refreshBackups() {
  if (!selectedNodeId) return;
  const body = document.getElementById("backups-body");
  let backups;
  try {
    backups = await api(`/api/nodes/${selectedNodeId}/backups`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("backups-count").textContent = backups.length;
  if (backups.length === 0) {
    body.innerHTML = `<div class="empty">Бэкапов ещё нет — сними первый выше</div>`;
    return;
  }
  body.innerHTML = backups
    .map((b) => {
      let statusHtml;
      if (b.error) {
        statusHtml = `<span style="color:var(--crit)">ошибка: ${escapeHtml(b.error)}</span>`;
      } else if (b.changed) {
        statusHtml = `<span style="color:var(--warn)">изменился</span>`;
      } else {
        statusHtml = `<span style="color:var(--text-dim)">без изменений</span>`;
      }
      const diffBtn = !b.error ? `<button data-id="${b.id}" class="show-diff">diff</button>` : "";
      return `
        <div class="channel-row">
          <span>${timeAgo(b.taken_at)} · ${b.size} байт · ${statusHtml}</span>
          ${diffBtn}
        </div>`;
    })
    .join("");
  body.querySelectorAll(".show-diff").forEach((btn) => {
    btn.addEventListener("click", () => showDiff(btn.dataset.id));
  });
}

document.getElementById("run-backup").addEventListener("click", async () => {
  const username = document.getElementById("b-user").value.trim() || null;
  const command = document.getElementById("b-cmd").value.trim();
  const key_path = document.getElementById("b-key").value.trim();
  const port = Number(document.getElementById("b-port").value) || 22;
  if (!command) return toast("Укажи команду (например: show running-config)", true);
  try {
    const result = await apiWithCredentials(`/api/nodes/${selectedNodeId}/backup`, {
      method: "POST",
      body: JSON.stringify({ username, command, key_path: key_path || null, port }),
    });
    if (result.error) {
      toast("Бэкап не снят: " + result.error, true);
    } else {
      toast(result.changed ? "Бэкап снят — конфигурация изменилась" : "Бэкап снят — без изменений");
    }
    refreshBackups();
  } catch (e) {
    toast(e.message, true);
  }
});

const diffModal = document.getElementById("diff-modal");
document.getElementById("diff-close").addEventListener("click", () => diffModal.close());

async function showDiff(backupId) {
  document.getElementById("diff-modal-id").textContent = `#${backupId}`;
  const pre = document.getElementById("diff-content");
  pre.textContent = "загрузка…";
  diffModal.showModal();
  try {
    const result = await api(`/api/backups/${backupId}/diff`);
    pre.textContent = result.diff || result.detail || "нет изменений";
  } catch (e) {
    pre.textContent = e.message;
  }
}

function onKeySaved() {
  loadNodePicker();
  loadGroupPicker();
}

loadNodePicker();
loadGroupPicker();
