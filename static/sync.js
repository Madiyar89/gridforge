// Площадки (Sync Node) — регистрация + просмотр последних отчётов.

async function refreshSites() {
  const body = document.getElementById("sites-body");
  let sites;
  try {
    sites = await api("/api/sync/sites");
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("sites-count").textContent = sites.length;
  if (sites.length === 0) {
    body.innerHTML = `<div class="empty">Площадок ещё нет — заведи выше</div>`;
    return;
  }
  body.innerHTML = sites
    .map((s) => {
      const r = s.last_report;
      const meta = r
        ? `последний отчёт: ${new Date(r.received_at).toLocaleString("ru-RU")} · узлов: ${r.node_count}`
        : `ещё не звонила`;
      const counts = r
        ? `<div class="site-counts">
             <span class="crit">critical: ${r.incidents_critical}</span>
             <span class="warn">warning: ${r.incidents_warning}</span>
             <span>info: ${r.incidents_info}</span>
           </div>`
        : "";
      const incidents = r && r.incidents && r.incidents.length
        ? r.incidents
            .map((i) => `<div class="site-incident-row">[${escapeHtml(i.severity)}] ${escapeHtml(i.node)}: ${escapeHtml(i.watch_label)}</div>`)
            .join("")
        : "";
      return `<div class="site-card" data-id="${s.id}">
        <div class="site-head">
          <span><b>${escapeHtml(s.label)}</b></span>
          <button type="button" class="btn-ghost del-site" data-id="${s.id}" data-label="${escapeHtml(s.label)}">удалить</button>
        </div>
        <div class="site-meta">${meta}</div>
        ${counts}
        ${incidents}
      </div>`;
    })
    .join("");

  body.querySelectorAll(".del-site").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить площадку «${btn.dataset.label}»? Её токен перестанет работать.`)) return;
      try {
        await api(`/api/sync/sites/${btn.dataset.id}`, { method: "DELETE" });
        toast("Площадка удалена");
        refreshSites();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("add-site").addEventListener("click", async () => {
  const label = document.getElementById("new-site-label").value.trim();
  if (!label) return toast("Укажи имя площадки", true);
  try {
    const r = await api("/api/sync/sites", { method: "POST", body: JSON.stringify({ label }) });
    const box = document.getElementById("new-site-token");
    box.style.display = "";
    box.innerHTML = `Токен площадки «${escapeHtml(r.label)}» (показывается один раз):<br><b>${escapeHtml(r.token)}</b><br><br>На удалённом инстансе задать перед стартом:<br>GRIDFORGE_SYNC_HUB_URL=${escapeHtml(location.origin)}<br>GRIDFORGE_SYNC_TOKEN=${escapeHtml(r.token)}`;
    document.getElementById("new-site-label").value = "";
    toast("Площадка добавлена");
    refreshSites();
  } catch (e) {
    toast(e.message, true);
  }
});

function onKeySaved() {
  refreshSites();
}

refreshSites();
setInterval(refreshSites, REFRESH_MS);
