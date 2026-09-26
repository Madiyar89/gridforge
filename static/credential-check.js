// Проверка доступа — SMB-учётка на узлах группы, только успех/отказ,
// без выполнения команд. Пароль нигде не хранится клиентом дольше,
// чем нужно на сам запрос.

let _ccGroupId = null;
let _ccRunId = null;
let _ccVlans = [];

async function refreshCcGroups() {
  const select = document.getElementById("cc-group-select");
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  const previous = select.value;
  select.innerHTML =
    `<option value="">выбери группу…</option>` +
    groups.map((g) => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
  if (previous) select.value = previous;
}

async function refreshCcVlans() {
  const select = document.getElementById("cc-vlan-select");
  select.innerHTML = `<option value="">вся группа (все узлы)</option>`;
  select.disabled = true;
  _ccVlans = [];
  if (!_ccGroupId) return;
  let vlans;
  try {
    vlans = await api("/api/vlans");
  } catch (e) {
    return;
  }
  _ccVlans = vlans.filter((v) => String(v.group_id) === String(_ccGroupId));
  if (_ccVlans.length === 0) return;
  select.innerHTML =
    `<option value="">вся группа (все узлы)</option>` +
    _ccVlans.map((v) => `<option value="${v.id}">${escapeHtml(v.name)}${v.vlan_id ? " (VLAN " + v.vlan_id + ")" : ""} · ${escapeHtml(v.cidr)}</option>`).join("");
  select.disabled = false;
}

document.getElementById("cc-group-select").addEventListener("change", () => {
  _ccGroupId = document.getElementById("cc-group-select").value || null;
  _ccRunId = null;
  document.getElementById("cc-targets-body").innerHTML = `<div class="empty">Выбери прогон слева</div>`;
  document.getElementById("cc-targets-count").textContent = "";
  refreshCcVlans();
  if (!_ccGroupId) {
    document.getElementById("cc-runs-body").innerHTML = `<div class="empty">Выбери группу выше</div>`;
    document.getElementById("cc-runs-count").textContent = "";
    return;
  }
  refreshCcRuns();
});

function updateRunButtonState() {
  const consent = document.getElementById("cc-consent").checked;
  document.getElementById("cc-run").disabled = !consent;
}
document.getElementById("cc-consent").addEventListener("change", updateRunButtonState);

document.getElementById("cc-run").addEventListener("click", async () => {
  if (!_ccGroupId) return toast("Выбери группу", true);
  const username = document.getElementById("cc-username").value.trim();
  const password = document.getElementById("cc-password").value;
  const domain = document.getElementById("cc-domain").value.trim() || null;
  const consent_confirmed = document.getElementById("cc-consent").checked;
  const vlanRaw = document.getElementById("cc-vlan-select").value;
  const vlan_id = vlanRaw ? Number(vlanRaw) : null;
  if (!username) return toast("Укажи логин", true);
  if (!password) return toast("Укажи пароль", true);
  if (!consent_confirmed) return toast("Подтверди разрешение на тестирование", true);

  const btn = document.getElementById("cc-run");
  btn.disabled = true;
  btn.textContent = "Проверяю…";
  try {
    const result = await api(`/api/groups/${_ccGroupId}/credential-checks`, {
      method: "POST",
      body: JSON.stringify({ username, password, domain, consent_confirmed, vlan_id }),
    });
    toast(`Запущено — целей: ${result.targets}`);
    document.getElementById("cc-password").value = "";
    refreshCcRuns();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.textContent = "Проверить";
    updateRunButtonState();
  }
});

const CC_STATUS_LABEL = { running: "выполняется", done: "завершено", failed: "ошибка" };

async function refreshCcRuns() {
  const body = document.getElementById("cc-runs-body");
  if (!_ccGroupId) return;
  let runs;
  try {
    runs = await api(`/api/groups/${_ccGroupId}/credential-checks`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("cc-runs-count").textContent = runs.length;
  if (runs.length === 0) {
    body.innerHTML = `<div class="empty">Проверок ещё не было</div>`;
    return;
  }
  body.innerHTML = runs
    .map((r) => `
      <div class="cc-row${String(r.id) === String(_ccRunId) ? " active" : ""}" data-id="${r.id}">
        <div class="top">
          <span>${escapeHtml(r.username)}${r.domain ? "@" + escapeHtml(r.domain) : ""} · SMB</span>
          <span>${CC_STATUS_LABEL[r.status] || r.status}</span>
        </div>
        <div class="meta">${timeAgo(r.started_at)} · успешно ${r.success_count}/${r.target_count} · ${r.vlan_name ? "VLAN " + escapeHtml(r.vlan_name) : "вся группа"} · запросил: ${escapeHtml(r.triggered_by)}</div>
      </div>`)
    .join("");
  body.querySelectorAll(".cc-row").forEach((el) => {
    el.addEventListener("click", () => loadCcTargets(el.dataset.id));
  });
}

async function loadCcTargets(runId) {
  _ccRunId = runId;
  refreshCcRuns();
  const body = document.getElementById("cc-targets-body");
  body.innerHTML = `<div class="empty">Загрузка…</div>`;
  let targets;
  try {
    targets = await api(`/api/credential-checks/${runId}/targets`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("cc-targets-count").textContent = targets.length;
  if (targets.length === 0) {
    body.innerHTML = `<div class="empty">Результатов пока нет</div>`;
    return;
  }
  body.innerHTML = targets
    .map((t) => `
      <div class="cc-target">
        <span style="font-family:var(--mono)">${escapeHtml(t.address)}</span>
        ${t.ok
          ? `<span class="cc-ok">доступ есть</span>`
          : `<span class="cc-fail">${escapeHtml(t.error || "отказано")}</span>`}
      </div>`)
    .join("");
}

function onKeySaved() {
  refreshCcGroups();
}

refreshCcGroups();
updateRunButtonState();
setInterval(() => {
  if (_ccGroupId) refreshCcRuns();
}, REFRESH_MS);
