// Рубка — одна читающая команда сразу на набор узлов.
//
// Учётка (логин/пароль или ключ) спрашивается перед запуском и никуда не
// сохраняется: на сервере она тоже живёт только в пределах запроса — тот
// же принцип, что у бэкапа и SSH-консоли.

let _selected = new Set();
let _watchedSweepId = null;
let _pollTimer = null;

async function refreshNodes() {
  const body = document.getElementById("nodes-body");
  let nodes;
  try {
    nodes = await api("/api/nodes");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (nodes.length === 0) {
    body.innerHTML = `<div class="empty">Узлов нет — заведи их в Инвентаре</div>`;
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
  refreshPresets();
  refreshHistory();
}

refreshNodes();
refreshPresets();
refreshHistory();
