// Сценарии — массовая смена конфигурации на наборе узлов (NTP, баннер,
// логи, AAA...). В отличие от Рубки (rubka.js, только чтение) команды
// здесь меняют конфигурацию, поэтому каталог сценариев фиксированный:
// список приходит с сервера, свой текст команды тут не пишут.
//
// Учётка спрашивается перед запуском и никуда не сохраняется — тот же
// принцип, что у Рубки/бэкапа/SSH-консоли.

let _selected = new Set();
let _scenarios = [];
let _activeScenario = null;
let _pollTimer = null;
let _allNodes = [];
let _groupFilter = "";

const CATEGORY_LABELS = {
  config: "Конфигурация",
  security: "Безопасность",
};

// naturalCompare/sortNodesNatural — см. common.js, общие для всех страниц.

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
  if (_groupFilter) {
    // Выбор группы заменяет отметку — только узлы этой группы, а не
    // добавляет к уже стоящей (см. тот же фикс в rubka.js).
    _selected = new Set(
      _allNodes.filter((n) => String(n.group_id ?? "") === _groupFilter).map((n) => n.id)
    );
  }
  renderNodeList();
});

async function refreshNodes() {
  const body = document.getElementById("nodes-body");
  try {
    _allNodes = sortNodesNatural(await api("/api/nodes"));
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
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

async function refreshScenarios() {
  const listEl = document.getElementById("scenarios-list");
  try {
    _scenarios = await api("/api/scenarios");
  } catch (e) {
    listEl.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (_scenarios.length === 0) {
    listEl.innerHTML = `<div class="empty">Сценариев нет</div>`;
    return;
  }
  const byCategory = {};
  for (const s of _scenarios) {
    const cat = s.category || "прочее";
    (byCategory[cat] = byCategory[cat] || []).push(s);
  }
  listEl.innerHTML = Object.entries(byCategory)
    .map(
      ([cat, items]) => `
      <div class="scn-cat">${escapeHtml(CATEGORY_LABELS[cat] || cat)}</div>
      ${items
        .map(
          (s) => `
        <button type="button" class="scn-btn" data-id="${s.id}">
          <b>${escapeHtml(s.label)}</b>
          <span>${s.vendors.map(escapeHtml).join(", ")}</span>
        </button>`
        )
        .join("")}`
    )
    .join("");
  listEl.querySelectorAll(".scn-btn").forEach((btn) => {
    btn.addEventListener("click", () => selectScenario(Number(btn.dataset.id)));
  });
}

function selectScenario(id) {
  _activeScenario = _scenarios.find((s) => s.id === id) || null;
  document.querySelectorAll(".scn-btn").forEach((btn) => {
    btn.classList.toggle("active", Number(btn.dataset.id) === id);
  });
  openScenarioModal();
}

function openScenarioModal() {
  if (!_activeScenario) return;
  if (_selected.size === 0) return toast("Сначала выбери узлы (шаг 1)", true);

  document.getElementById("scn-modal-title").textContent = _activeScenario.label;
  const fieldsEl = document.getElementById("scn-modal-fields");
  const paramFields = _activeScenario.params
    .map(
      (p) => `
      <label for="param-${escapeHtml(p)}">${escapeHtml(p)}
        <input id="param-${escapeHtml(p)}" data-param="${escapeHtml(p)}">
      </label>`
    )
    .join("");
  fieldsEl.innerHTML =
    paramFields || `<div style="font-size:12px;color:var(--text-dim);">Этот сценарий не требует параметров.</div>`;
  document.getElementById("scn-modal").showModal();
}

document.getElementById("scn-modal-cancel").addEventListener("click", () => {
  document.getElementById("scn-modal").close();
});
document.getElementById("run-scenario-btn").addEventListener("click", runActiveScenario);

// Учётка — центральная (Настройки → Учётки), своя на группу узла;
// ручной prompt — только если сервер ответит, что нет ни центральной,
// ни явной учётки (см. apiWithCredentials в common.js).

async function runActiveScenario() {
  if (!_activeScenario) return;
  if (_selected.size === 0) return toast("Не выбрано ни одного узла", true);

  const params = {};
  document.querySelectorAll("[data-param]").forEach((input) => {
    params[input.dataset.param] = input.value.trim();
  });
  for (const p of _activeScenario.params) {
    if (!params[p]) return toast(`Заполни параметр: ${p}`, true);
  }

  if (!confirm(`Сценарий «${_activeScenario.label}» изменит конфигурацию на ${_selected.size} узлах. Продолжить?`)) {
    return;
  }

  try {
    const started = await apiWithCredentials(`/api/scenarios/${_activeScenario.id}/run`, {
      method: "POST",
      body: JSON.stringify({ node_ids: [..._selected], params }),
    });
    document.getElementById("scn-modal").close();
    toast(`Запущено на ${started.nodes} узлах`);
    if (started.skipped && started.skipped.length) {
      toast(`Пропущены: ${started.skipped.join(", ")}`, true);
    }
    watchRun(started.id);
    refreshHistory();
  } catch (e) {
    toast(e.message, true);
  }
}

function watchRun(runId) {
  clearInterval(_pollTimer);
  const tick = async () => {
    let data;
    try {
      data = await api(`/api/scenario-runs/${runId}`);
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

  document.getElementById("results-body").innerHTML = [...data.results]
    .sort((a, b) => naturalCompare(a.node_name, b.node_name))
    .map((r) => {
      if (r.ok === null) {
        return `<details class="result-row"><summary><b>${escapeHtml(r.node_name)}</b> <span class="pending-text">выполняется…</span></summary></details>`;
      }
      const dot = r.ok ? `<span class="ok-dot up"></span>` : `<span class="ok-dot down"></span>`;
      const status = r.ok ? "" : `<span class="err-text">${escapeHtml(r.error || "ошибка")}</span>`;
      const body = r.output ? `<pre>${escapeHtml(r.output)}</pre>` : "";
      // Открыто по умолчанию только у ошибок — успешные узлы сворачиваем,
      // чтобы длинный вывод (например, текст баннера) не растягивал
      // список на весь экран и не мешал искать неудачные узлы.
      return `<details class="result-row"${r.ok ? "" : " open"}><summary>${dot}<b>${escapeHtml(r.node_name)}</b>${status}</summary>${body}</details>`;
    })
    .join("");
}

async function refreshHistory() {
  const body = document.getElementById("history-body");
  let runs;
  try {
    runs = await api("/api/scenario-runs?limit=15");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (runs.length === 0) {
    body.innerHTML = `<div class="empty">Прогонов ещё не было</div>`;
    return;
  }
  body.innerHTML = runs
    .map(
      (r) => `
      <div class="channel-row">
        <span>
          <b>${escapeHtml(r.label)}</b> · ${r.total} узл.
          ${r.failed ? `· <span style="color:var(--crit)">ошибок ${r.failed}</span>` : ""}
          <br><span class="addr">${escapeHtml(r.started_by)} · ${timeAgo(r.started_at)}</span>
        </span>
        <button data-id="${r.id}" class="show-run">открыть</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".show-run").forEach((btn) => {
    btn.addEventListener("click", () => watchRun(Number(btn.dataset.id)));
  });
}

function onKeySaved() {
  refreshNodes();
  refreshGroups();
  refreshScenarios();
  refreshHistory();
}

refreshNodes();
refreshGroups();
refreshScenarios();
refreshHistory();
