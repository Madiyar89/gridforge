// Каналы уведомлений — webhook/telegram.

let _nodesById = {};

async function refreshNodeOptions() {
  const select = document.getElementById("new-channel-node");
  let nodes;
  try {
    nodes = await api("/api/nodes");
  } catch (e) {
    return;
  }
  _nodesById = Object.fromEntries(nodes.map((n) => [n.id, n.name]));
  select.innerHTML =
    `<option value="">все узлы</option>` +
    nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
}

async function refreshChannels() {
  const body = document.getElementById("channels-body");
  let channels;
  try {
    channels = await api("/api/channels");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("channels-count").textContent = channels.length;
  if (channels.length === 0) {
    body.innerHTML = `<div class="empty">Каналов нет — добавь ниже</div>`;
    return;
  }
  body.innerHTML = channels
    .map((c) => {
      const scope = c.node_id ? `узел: ${escapeHtml(_nodesById[c.node_id] || `#${c.node_id}`)}` : "все узлы";
      return `
      <div class="channel-row">
        <span><span class="kind">${escapeHtml(c.kind)}</span> · min ${escapeHtml(c.min_severity)} · ${scope}</span>
        <button data-id="${c.id}" class="del-channel">удалить</button>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".del-channel").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/channels/${btn.dataset.id}`, { method: "DELETE" });
        toast("Канал удалён");
        refreshChannels();
        refreshChannelOptions();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-channel").addEventListener("click", async () => {
  const kind = document.getElementById("new-channel-kind").value;
  const target = document.getElementById("new-channel-target").value.trim();
  const min_severity = document.getElementById("new-channel-severity").value;
  const nodeValue = document.getElementById("new-channel-node").value;
  const node_id = nodeValue ? Number(nodeValue) : null;
  if (!target) return toast("Заполни поле канала", true);
  let config;
  if (kind === "webhook") {
    config = { url: target };
  } else {
    const [bot_token, chat_id] = target.split(",").map((s) => s.trim());
    if (!bot_token || !chat_id) return toast("Формат: bot_token,chat_id", true);
    config = { bot_token, chat_id };
  }
  try {
    await api("/api/channels", { method: "POST", body: JSON.stringify({ kind, config, min_severity, node_id }) });
    document.getElementById("new-channel-target").value = "";
    toast("Канал добавлен");
    refreshChannels();
    refreshChannelOptions();
  } catch (e) {
    toast(e.message, true);
  }
});

async function refreshChannelOptions() {
  const select = document.getElementById("new-step-channel");
  let channels;
  try {
    channels = await api("/api/channels");
  } catch (e) {
    return;
  }
  select.innerHTML = channels
    .map((c) => `<option value="${c.id}">#${c.id} · ${escapeHtml(c.kind)}</option>`)
    .join("");
}

async function refreshEscalationSteps() {
  const body = document.getElementById("escalation-steps-body");
  let steps;
  try {
    steps = await api("/api/escalation-steps");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("escalation-steps-count").textContent = steps.length;
  if (steps.length === 0) {
    body.innerHTML = `<div class="empty">Шагов эскалации нет — только исходная рассылка при открытии</div>`;
    return;
  }
  body.innerHTML = steps
    .map(
      (s) => `
      <div class="channel-row">
        <span>через ${s.delay_minutes} мин → канал #${s.channel_id}</span>
        <button data-id="${s.id}" class="del-escalation-step">удалить</button>
      </div>`
    )
    .join("");
  body.querySelectorAll(".del-escalation-step").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        await api(`/api/escalation-steps/${btn.dataset.id}`, { method: "DELETE" });
        toast("Шаг удалён");
        refreshEscalationSteps();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-escalation-step").addEventListener("click", async () => {
  const delay_minutes = Number(document.getElementById("new-step-delay").value);
  const channel_id = Number(document.getElementById("new-step-channel").value);
  if (!delay_minutes || delay_minutes <= 0) return toast("Укажи задержку в минутах", true);
  if (!channel_id) return toast("Нет доступных каналов — добавь канал выше", true);
  try {
    await api("/api/escalation-steps", { method: "POST", body: JSON.stringify({ delay_minutes, channel_id }) });
    document.getElementById("new-step-delay").value = "";
    toast("Шаг эскалации добавлен");
    refreshEscalationSteps();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshNodeOptions();
  refreshChannels();
  refreshChannelOptions();
  refreshEscalationSteps();
}

refreshNodeOptions();
refreshChannels();
refreshChannelOptions();
refreshEscalationSteps();
setInterval(refreshChannels, REFRESH_MS);
