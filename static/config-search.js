// Поиск по конфигурациям — grep по самому свежему бэкапу каждого узла,
// перенесено из NetOpsHub (Отчётность -> Отчёты -> Поиск).

async function runConfigSearch() {
  const q = document.getElementById("cs-query").value.trim();
  const body = document.getElementById("cs-body");
  if (!q) return;
  body.innerHTML = `<div class="empty">Ищу…</div>`;
  let data;
  try {
    data = await api(`/api/reports/search?q=${encodeURIComponent(q)}`);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  const matches = data.matches || [];
  if (matches.length === 0) {
    body.innerHTML = `<div class="empty">Совпадений не найдено</div>`;
    return;
  }
  body.innerHTML = `<table class="risk-rules-table"><thead><tr>
    <th>Устройство</th><th>Строка</th><th>Совпадение</th>
  </tr></thead><tbody>${matches
    .map(
      (m) => `<tr>
      <td class="name">${escapeHtml(m.hostname)}</td>
      <td style="font-family:var(--mono);color:var(--text-dim)">${m.line_number}</td>
      <td style="font-family:var(--mono);overflow-wrap:anywhere">${escapeHtml(m.line)}</td>
    </tr>`
    )
    .join("")}</tbody></table>`;
}

document.getElementById("cs-search").addEventListener("click", runConfigSearch);
document.getElementById("cs-query").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runConfigSearch();
});
