// Рубка — одна читающая команда сразу на набор узлов.
//
// Учётка (логин/пароль или ключ) спрашивается перед запуском и никуда не
// сохраняется: на сервере она тоже живёт только в пределах запроса — тот
// же принцип, что у бэкапа и SSH-консоли.

let _selected = new Set();
let _watchedSweepId = null;
let _pollTimer = null;
let _allNodes = [];
let _groupFilter = "";

// Естественная сортировка: "LAB-2" перед "LAB-10" — обычное
// лексикографическое сравнение ставит "LAB-10" раньше "LAB-2", здесь
// строка режется на числовые/нечисловые куски и числа сравниваются как
// числа, а не как строки посимвольно.
function naturalCompare(a, b) {
  const ax = String(a).match(/\d+|\D+/g) || [];
  const bx = String(b).match(/\d+|\D+/g) || [];
  const len = Math.max(ax.length, bx.length);
  for (let i = 0; i < len; i++) {
    const av = ax[i] ?? "";
    const bv = bx[i] ?? "";
    if (av === bv) continue;
    const an = Number(av);
    const bn = Number(bv);
    if (!Number.isNaN(an) && !Number.isNaN(bn) && av !== "" && bv !== "") {
      if (an !== bn) return an - bn;
    }
    return av < bv ? -1 : 1;
  }
  return 0;
}

async function refreshGroups() {
  const select = document.getElementById("group-select");
  let groups;
  try {
    groups = await api("/api/groups");
  } catch (e) {
    return;
  }
  const current = select.value;
  select.innerHTML =
    `<option value="">Все группы</option>` +
    groups
      .map((g) => `<option value="${g.id}">${escapeHtml(g.name)} (${g.node_count})</option>`)
      .join("");
  select.value = current;
}

document.getElementById("group-select").addEventListener("change", (e) => {
  _groupFilter = e.target.value;
  renderNodeList();
  if (_groupFilter) {
    // Выбор группы сразу отмечает все её узлы — не нужно ещё раз жать
    // "выбрать все" после того, как уже сузил список группой.
    _allNodes
      .filter((n) => String(n.group_id ?? "") === _groupFilter)
      .forEach((n) => _selected.add(n.id));
    renderNodeList();
  }
});

async function refreshNodes() {
  const body = document.getElementById("nodes-body");
  try {
    _allNodes = await api("/api/nodes");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  _allNodes.sort((a, b) => naturalCompare(a.name, b.name));
  renderNodeList();
}

function renderNodeList() {
  const body = document.getElementById("nodes-body");
  const nodes = _groupFilter
    ? _allNodes.filter((n) => String(n.group_id ?? "") === _groupFilter)
    : _allNodes;
  if (nodes.length === 0) {
    body.innerHTML = `<div class="empty">${_allNodes.length === 0 ? "Узлов нет — заведи их в Инвентаре" : "В этой группе узлов нет"}</div>`;
    updatePickedCount();
    return;
  }
  body.innerHTML = nodes
    .map(
      (n) => `
      <label class="node-pick">
        <input type="checkbox" class="node-cb" value="${n.id}" ${_selected.has(n.id) ? "checked" : ""}>
        <span>
          ${escapeHtml(n.name)}
          ${n.vendor ? `<span class="vendor-badge">${escapeHtml(n.vendor)}</span>` : ""}
          <br><span class="addr">${escapeHtml(n.address)}</span>
        </span>
      </label>`
    )
    .join("");
  body.querySelectorAll(".node-cb").forEach((cb) => {
    cb.addEventListener("change", () => {
      const id = Number(cb.value);
      cb.checked ? _selected.add(id) : _selected.delete(id);
      updatePickedCount();
    });
  });
  updatePickedCount();
}

function updatePickedCount() {
  document.getElementById("picked-count").textContent = `${_selected.size} узлов`;
}

document.getElementById("pick-all").addEventListener("click", () => {
  document.querySelectorAll(".node-cb").forEach((cb) => {
    cb.checked = true;
    _selected.add(Number(cb.value));
  });
  updatePickedCount();
});

document.getElementById("pick-none").addEventListener("click", () => {
  document.querySelectorAll(".node-cb").forEach((cb) => (cb.checked = false));
  _selected.clear();
  updatePickedCount();
});

async function refreshPresets() {
  let presets;
  try {
    presets = await api("/api/sweep-presets");
  } catch (e) {
    return;
  }
  document.getElementById("presets").innerHTML = presets
    .map(
      (p) => `
      <button type="button" class="cmd-btn" data-key="${escapeHtml(p.key)}">
        <b>${escapeHtml(p.label)}</b>
        <span>${escapeHtml(p.hint)}</span>
      </button>`
    )
    .join("");
  document.querySelectorAll(".cmd-btn").forEach((btn) => {
    btn.addEventListener("click", () => runSweep({ preset_key: btn.dataset.key }));
  });
}

document.getElementById("run-custom").addEventListener("click", () => {
  const command = document.getElementById("custom-command").value.trim();
  if (!command) return toast("Введи команду", true);
  runSweep({ command });
});

function askCredentials() {
  // Спрашиваем каждый раз: пароль от боевого оборудования не должен
  // оседать ни в localStorage, ни в полях формы между заходами.
  const username = prompt("Логин для подключения к узлам:");
  if (!username) return null;
  const password = prompt("Пароль (пусто — если вход по ключу):") || null;
  return { username, password };
}

async function runSweep(what) {
  if (_selected.size === 0) return toast("Не выбрано ни одного узла", true);
  const creds = askCredentials();
  if (!creds) return;

  try {
    const started = await api("/api/sweeps", {
      method: "POST",
      body: JSON.stringify({ node_ids: [..._selected], ...what, ...creds }),
    });
    toast(`Запущено на ${started.nodes} узлах`);
    document.getElementById("custom-command").value = "";
    watchSweep(started.id);
    refreshHistory();
  } catch (e) {
    toast(e.message, true);
  }
}

function watchSweep(sweepId) {
  _watchedSweepId = sweepId;
  clearInterval(_pollTimer);
  const tick = async () => {
    let data;
    try {
      data = await api(`/api/sweeps/${sweepId}`);
    } catch (e) {
      clearInterval(_pollTimer);
      return;
    }
    renderResults(data);
    if (data.status === "done") {
      clearInterval(_pollTimer);
      refreshHistory();
    }
  };
  tick();
  _pollTimer = setInterval(tick, 2000);
}

function renderResults(data) {
  document.getElementById("progress-label").textContent =
    `${escapeHtml(data.label)} · готово ${data.done} из ${data.total}` +
    (data.failed ? ` · ошибок ${data.failed}` : "");

  document.getElementById("results-body").innerHTML = data.results
    .map((r) => {
      if (r.ok === null) {
        return `<div class="result-row"><b>${escapeHtml(r.node_name)}</b> <span class="addr">— опрашивается…</span></div>`;
      }
      const head = r.ok
        ? `<span class="ok-dot up"></span><b>${escapeHtml(r.node_name)}</b>`
        : `<span class="ok-dot down"></span><b>${escapeHtml(r.node_name)}</b> <span style="color:var(--crit)">${escapeHtml(r.error || "ошибка")}</span>`;
      const body = r.ok && r.output ? `<pre>${escapeHtml(r.output)}</pre>` : "";
      return `<div class="result-row">${head} <span class="addr">${escapeHtml(r.command)}</span>${body}</div>`;
    })
    .join("");
}

async function refreshHistory() {
  const body = document.getElementById("history-body");
  let sweeps;
  try {
    sweeps = await api("/api/sweeps?limit=15");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (sweeps.length === 0) {
    body.innerHTML = `<div class="empty">Прогонов ещё не было</div>`;
    return;
  }
  body.innerHTML = sweeps
    .map(
      (s) => `
      <div class="channel-row">
        <span>
          <b>${escapeHtml(s.label)}</b> · ${s.total} узл.
          ${s.failed ? `· <span style="color:var(--crit)">ошибок ${s.failed}</span>` : ""}
          <br><span class="addr">${escapeHtml(s.started_by)} · ${timeAgo(s.started_at)}</span>
        </span>
        <button data-id="${s.id}" class="show-sweep">открыть</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".show-sweep").forEach((btn) => {
    btn.addEventListener("click", () => watchSweep(Number(btn.dataset.id)));
  });
}

function onKeySaved() {
  refreshNodes();
  refreshGroups();
  refreshPresets();
  refreshHistory();
}

refreshNodes();
refreshGroups();
refreshPresets();
refreshHistory();
