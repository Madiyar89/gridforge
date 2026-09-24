// Syslog — просмотр принятых сообщений, фильтр по узлу.

const SEV_ICON = { 0: "🔴", 1: "🔴", 2: "🔴", 3: "🟠", 4: "🟡", 5: "🔵", 6: "⚪", 7: "⚪" };

async function loadNodeFilter() {
  const select = document.getElementById("syslog-node-filter");
  try {
    const nodes = sortNodesNatural(await api("/api/nodes"));
    const prev = select.value;
    select.innerHTML = `<option value="">все узлы</option>` + nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)}</option>`).join("");
    select.value = prev;
  } catch (e) {
    /* тихо — фильтр не критичен для просмотра */
  }
}

async function refreshSyslog() {
  const body = document.getElementById("syslog-body");
  const nodeId = document.getElementById("syslog-node-filter").value;
  const path = nodeId ? `/api/syslog?node_id=${nodeId}` : "/api/syslog";
  let messages;
  try {
    messages = await api(path);
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
    return;
  }
  document.getElementById("syslog-count").textContent = messages.length;
  if (messages.length === 0) {
    body.innerHTML = `<div class="empty">Сообщений пока нет</div>`;
    return;
  }
  body.innerHTML = messages
    .map((m) => {
      const icon = m.severity !== null ? SEV_ICON[m.severity] || "⚪" : "⚪";
      const time = new Date(m.received_at).toLocaleTimeString("ru-RU");
      const geoParts = [];
      if (m.geo) {
        if (m.geo.country) geoParts.push(m.geo.country);
        if (m.geo.as_org) geoParts.push(m.geo.as_org);
      }
      const geo = geoParts.length ? ` <span class="geo" style="color:var(--text-dim);font-size:11px">[${escapeHtml(geoParts.join(" · "))}]</span>` : "";
      return `<div class="syslog-row">
        <span class="sev">${icon}</span>
        <span class="time">${time}</span>
        <span class="src">${escapeHtml(m.source_ip)}${geo}</span>
        <span class="msg">${escapeHtml(m.message)}</span>
      </div>`;
    })
    .join("");
}

function countryFlag(iso) {
  if (!iso || iso.length !== 2) return "";
  const codePoints = [...iso.toUpperCase()].map((c) => 0x1f1e6 - 65 + c.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

async function runGeoLookup() {
  const ip = document.getElementById("geo-q").value.trim();
  const out = document.getElementById("geo-result");
  if (!ip) return toast("Укажи IP", true);
  out.textContent = "ищу…";
  try {
    const r = await api(`/api/geoip-lookup?ip=${encodeURIComponent(ip)}`);
    if (!r.geo) {
      out.innerHTML = `<span style="color:var(--text-dim)">Нет данных — приватный/локальный адрес, либо база GeoLite2 ещё не настроена (см. страницу «Интеграции»)</span>`;
      return;
    }
    const flag = countryFlag(r.geo.country);
    const country = r.geo.country_name ? `${flag} ${escapeHtml(r.geo.country_name)} (${escapeHtml(r.geo.country)})` : "страна неизвестна";
    const asn = r.geo.asn ? `AS${r.geo.asn} · ${escapeHtml(r.geo.as_org || "")}` : "провайдер неизвестен";
    out.innerHTML = `<b>${escapeHtml(r.ip)}</b><br>${country}<br>${asn}`;
  } catch (e) {
    out.textContent = "ошибка: " + e.message;
  }
}

document.getElementById("run-geo").addEventListener("click", runGeoLookup);
document.getElementById("geo-q").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runGeoLookup();
});

document.getElementById("run-lookup").addEventListener("click", async () => {
  const q = document.getElementById("lookup-q").value.trim();
  const out = document.getElementById("lookup-result");
  if (!q) return toast("Введи IP или текст", true);
  out.textContent = "ищу…";
  try {
    const r = await api(`/api/ip-lookup?q=${encodeURIComponent(q)}`);
    if (r.match_count === 0) {
      out.textContent = "Ничего не найдено";
      return;
    }
    const parts = [];
    if (r.hostnames.length) parts.push(`hostname: ${r.hostnames.join(", ")}`);
    if (r.users.length) parts.push(`пользователь: ${r.users.join(", ")}`);
    out.textContent = `${r.match_count} совпадений` + (parts.length ? " — " + parts.join(" · ") : " — распознать hostname/пользователя не удалось");
  } catch (e) {
    out.textContent = "ошибка: " + e.message;
  }
});

document.getElementById("refresh-syslog").addEventListener("click", refreshSyslog);
document.getElementById("syslog-node-filter").addEventListener("change", refreshSyslog);

function onKeySaved() {
  loadNodeFilter();
  refreshSyslog();
}

loadNodeFilter();
refreshSyslog();
setInterval(refreshSyslog, REFRESH_MS);
