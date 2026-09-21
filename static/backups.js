// Бэкапы конфигураций — выбор узла, снятие снимка, история, diff.

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
}

loadNodePicker();
