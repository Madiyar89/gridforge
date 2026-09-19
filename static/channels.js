// Каналы уведомлений — webhook/telegram.

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
    .map(
      (c) => `
      <div class="channel-row">
        <span><span class="kind">${escapeHtml(c.kind)}</span> · min ${escapeHtml(c.min_severity)}</span>
        <button data-id="${c.id}" class="del-channel">удалить</button>
      </div>`
    )
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
    await api("/api/channels", { method: "POST", body: JSON.stringify({ kind, config, min_severity }) });
    document.getElementById("new-channel-target").value = "";
    toast("Канал добавлен");
    refreshChannels();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshChannels();
}

refreshChannels();
setInterval(refreshChannels, REFRESH_MS);
