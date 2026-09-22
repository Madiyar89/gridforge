// Поиск MAC-адреса по всему парку — живой опрос MAC-таблицы каждого узла.

async function runMacSearch() {
  const q = document.getElementById("mac-query").value.trim();
  const body = document.getElementById("mac-body");
  if (!q) return;
  body.innerHTML = `<div class="empty">Опрашиваю узлы — это может занять минуту…</div>`;
  let data;
  try {
    data = await api(`/api/reports/mac-search?q=${encodeURIComponent(q)}`, { method: "POST" });
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  if (data.error) {
    body.innerHTML = `<div class="empty">${escapeHtml(data.error)}</div>`;
    return;
  }
  const rows = data.rows || [];
  const skipped = data.skipped || [];
  let html = "";
  if (rows.length === 0) {
    html += `<div class="empty">Совпадений не найдено</div>`;
  } else {
    html += `<table class="risk-rules-table"><thead><tr>
      <th>MAC</th><th>Устройство</th><th>Порт</th><th>VLAN</th>
    </tr></thead><tbody>${rows
      .map(
        (r) => `<tr>
        <td style="font-family:var(--mono)">${escapeHtml(r.mac)}</td>
        <td class="name">${escapeHtml(r.hostname)}</td>
        <td style="font-family:var(--mono)">${escapeHtml(r.port)}</td>
        <td style="font-family:var(--mono);color:var(--text-dim)">${escapeHtml(r.vlan)}</td>
      </tr>`
      )
      .join("")}</tbody></table>`;
  }
  if (skipped.length > 0) {
    html += `<div class="hint">Пропущено: ${skipped.map(escapeHtml).join("; ")}</div>`;
  }
  body.innerHTML = html;
}

document.getElementById("mac-search-btn").addEventListener("click", runMacSearch);
document.getElementById("mac-query").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runMacSearch();
});
