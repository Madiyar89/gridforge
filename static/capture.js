// Захват трафика — запуск, история, анализ (протоколы/разговоры).

let selectedCaptureId = null;

async function refreshCaptures() {
  const body = document.getElementById("captures-body");
  let captures;
  try {
    captures = await api("/api/captures");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("captures-count").textContent = captures.length;
  if (captures.length === 0) {
    body.innerHTML = `<div class="empty">Захватов ещё не было</div>`;
    return;
  }
  body.innerHTML = captures
    .map((c) => {
      const statusColor = c.status === "done" ? "var(--ok)" : c.status === "failed" ? "var(--crit)" : "var(--warn)";
      const selectable = c.status === "done";
      return `
      <div class="channel-row ${selectable ? "cap-row" : ""}" data-id="${c.id}" style="${selectable ? "cursor:pointer" : ""}">
        <span><span style="color:${statusColor}">${escapeHtml(c.status)}</span> · ${escapeHtml(c.interface)}${c.bpf_filter ? " · " + escapeHtml(c.bpf_filter) : ""} <span class="count">· ${c.packet_count} пакетов</span></span>
        <span class="count">${timeAgo(c.started_at)}</span>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".cap-row").forEach((row) => {
    row.addEventListener("click", () => {
      selectedCaptureId = row.dataset.id;
      document.getElementById("analyze-protocols").disabled = false;
      document.getElementById("analyze-conversations").disabled = false;
      document.getElementById("analyze-output").textContent = `Захват #${selectedCaptureId} выбран — нажми «Иерархия протоколов» или «IP-разговоры»`;
    });
  });
}

async function runAnalyze(method) {
  const out = document.getElementById("analyze-output");
  out.textContent = "анализирую…";
  try {
    const result = await api(`/api/captures/${selectedCaptureId}/analyze?method=${method}`);
    out.textContent = result.output;
  } catch (e) {
    out.textContent = "ошибка: " + e.message;
  }
}
document.getElementById("analyze-protocols").addEventListener("click", () => runAnalyze("protocols"));
document.getElementById("analyze-conversations").addEventListener("click", () => runAnalyze("conversations"));

document.getElementById("run-capture").addEventListener("click", async () => {
  const iface = document.getElementById("c-iface").value.trim();
  const bpf = document.getElementById("c-bpf").value.trim();
  const duration = Number(document.getElementById("c-duration").value) || 30;
  if (!iface) return toast("Укажи интерфейс", true);

  const btn = document.getElementById("run-capture");
  btn.disabled = true;
  btn.textContent = `Захват (${duration}с)…`;
  try {
    const result = await api("/api/captures", {
      method: "POST",
      body: JSON.stringify({ interface: iface, bpf_filter: bpf || null, duration_seconds: duration }),
    });
    if (result.status === "failed") {
      toast("Захват не удался: " + result.error, true);
    } else {
      toast(`Захвачено ${result.packet_count} пакетов`);
    }
    refreshCaptures();
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = "Захватить";
  }
});

function onKeySaved() {
  refreshCaptures();
}

refreshCaptures();
