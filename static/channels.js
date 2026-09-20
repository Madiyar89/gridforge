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
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshNodeOptions();
  refreshChannels();
}

refreshNodeOptions();
refreshChannels();
setInterval(refreshChannels, REFRESH_MS);
