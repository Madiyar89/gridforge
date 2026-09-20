// Схема портов коммутатора по последнему снимку.

const STATE_LABEL = {
  up: "линк есть",
  notconnect: "кабель не подключён",
  disabled: "выключен вручную",
  "err-disabled": "отключён защитой",
  unknown: "состояние не распознано",
};

async function refreshNodeList() {
  const select = document.getElementById("node-select");
  let nodes;
  try {
    nodes = await api("/api/nodes");
  } catch (e) {
    return;
  }
  const previous = select.value;
  select.innerHTML = nodes
    .map((n) => `<option value="${n.id}">${escapeHtml(n.name)} — ${escapeHtml(n.address)}</option>`)
    .join("");
  if (previous) select.value = previous;
  if (select.value) loadPorts();
}

document.getElementById("node-select").addEventListener("change", loadPorts);

async function loadPorts() {
  const nodeId = document.getElementById("node-select").value;
  const body = document.getElementById("ports-body");
  if (!nodeId) return;

  let data;
  try {
    data = await api(`/api/nodes/${nodeId}/ports`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }

  const age = document.getElementById("snapshot-age");
  if (!data.taken_at) {
    age.textContent = "";
    body.innerHTML = `<div class="empty">Снимка ещё нет — нажми «Снять состояние»</div>`;
    document.getElementById("ports-summary").textContent = "";
    return;
  }

  // Возраст снимка показываем всегда: выключенный вчера порт иначе
  // выглядел бы как выключенный прямо сейчас.
  const ageText = `снято ${timeAgo(data.taken_at)}`;
  const stale = Date.now() - new Date(data.taken_at).getTime() > 24 * 3600 * 1000;
  age.innerHTML = stale ? `<span class="stale">${ageText}</span>` : ageText;

  if (!data.ok) {
    body.innerHTML = `<div class="empty">Последний снимок не удался: ${escapeHtml(data.error || "ошибка")}</div>`;
    return;
  }

  document.getElementById("ports-summary").textContent = Object.entries(data.summary)
    .map(([state, count]) => `${STATE_LABEL[state] || state}: ${count}`)
    .join(" · ");

  body.innerHTML =
    data.groups
      .map(
        (group) => `
        <div class="port-row-label">${
          group.ports.length === 1
            ? escapeHtml(group.ports[0].name)
            : `${escapeHtml(group.ports[0].name)} … ${escapeHtml(group.ports[group.ports.length - 1].name)} · ${group.ports.length} шт.`
        }</div>
        <div class="port-grid">
          ${group.ports
            .map((p, i) => {
              const num = p.name.split("/").pop();
              const cls = `port ${p.state}${p.is_trunk ? " trunk" : ""}`;
              return `<div class="${cls}" data-name="${escapeHtml(p.name)}" title="${escapeHtml(p.name)}">${escapeHtml(num)}</div>`;
            })
            .join("")}
        </div>`
      )
      .join("") +
    `
    <div class="port-legend">
      <span><i style="background:#1d3a28;border-color:#2f6b45"></i>линк есть</span>
      <span><i style="background:var(--surface-2)"></i>кабель не подключён</span>
      <span><i style="background:#3a1f1d;border-color:#6b2f2f"></i>выключен вручную</span>
      <span><i style="background:#4a1a16;border-color:#a33a2f"></i>отключён защитой</span>
      <span><i style="background:var(--surface-2);border-color:var(--info)"></i>уголок — trunk</span>
    </div>
    <div class="port-detail" id="port-detail"><span style="color:var(--text-dim)">Выбери порт на схеме</span></div>`;

  const byName = {};
  data.groups.forEach((g) => g.ports.forEach((p) => (byName[p.name] = p)));
  body.querySelectorAll(".port").forEach((el) => {
    el.addEventListener("click", () => {
      body.querySelectorAll(".port.selected").forEach((s) => s.classList.remove("selected"));
      el.classList.add("selected");
      showPortDetail(byName[el.dataset.name]);
    });
  });
}

function showPortDetail(port) {
  if (!port) return;
  document.getElementById("port-detail").innerHTML = `
    <b>${escapeHtml(port.name)}</b>
    <dl>
      <dt>Состояние</dt><dd>${escapeHtml(STATE_LABEL[port.state] || port.state)}</dd>
      <dt>Описание</dt><dd>${escapeHtml(port.description || "—")}</dd>
      <dt>VLAN</dt><dd>${escapeHtml(port.vlan || "—")}${port.is_trunk ? " (trunk)" : ""}</dd>
      <dt>Скорость</dt><dd>${escapeHtml(port.speed || "—")}</dd>
    </dl>`;
}

document.getElementById("refresh-ports").addEventListener("click", async () => {
  const nodeId = document.getElementById("node-select").value;
  if (!nodeId) return toast("Выбери узел", true);

  // Учётка спрашивается каждый раз и никуда не сохраняется — тот же
  // принцип, что в Рубке и при снятии бэкапа.
  const username = prompt("Логин для подключения к узлу:");
  if (!username) return;
  const password = prompt("Пароль (пусто — если вход по ключу):") || null;

  const btn = document.getElementById("refresh-ports");
  btn.disabled = true;
  btn.textContent = "Опрашиваю…";
  try {
    const result = await api(`/api/nodes/${nodeId}/ports/refresh`, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    if (result.ok) {
      toast(`Снято портов: ${result.ports}`);
    } else {
      toast(result.error || "Не удалось снять состояние", true);
    }
    loadPorts();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Снять состояние";
  }
});

function onKeySaved() {
  refreshNodeList();
}

refreshNodeList();
