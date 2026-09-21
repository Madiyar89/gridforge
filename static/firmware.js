// Версии ПО — хранилище файлов образов (загрузка/список/скачивание/удаление).

const VENDOR_LABELS = { cisco_ios: "Cisco IOS", junos: "Juniper Junos" };

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} Б`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} МБ`;
}

async function loadFirmware() {
  const container = document.getElementById("fw-lists");
  let data;
  try {
    data = await api("/api/firmware");
  } catch (e) {
    container.innerHTML = `<div class="panel"><div class="body"><div class="empty">${emptyOrError(e)}</div></div></div>`;
    return;
  }
  container.innerHTML = Object.entries(data)
    .map(([vendor, files]) => {
      const rows = files.length
        ? files
            .map(
              (f) => `<div class="channel-row">
          <span>${escapeHtml(f.filename)} <span class="count">· ${formatSize(f.size)}</span></span>
          <span style="display:flex;gap:6px;">
            <a class="icon-btn" href="/api/firmware/download?vendor=${encodeURIComponent(vendor)}&filename=${encodeURIComponent(f.filename)}">скачать</a>
            <button class="icon-btn fw-delete" data-vendor="${vendor}" data-filename="${escapeHtml(f.filename)}">удалить</button>
          </span>
        </div>`
            )
            .join("")
        : `<div class="empty">Образов нет</div>`;
      return `<div class="panel">
        <h2>${VENDOR_LABELS[vendor] || vendor} <span class="count">${files.length}</span></h2>
        <div class="body">${rows}</div>
      </div>`;
    })
    .join("");

  container.querySelectorAll(".fw-delete").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!confirm(`Удалить ${btn.dataset.filename}?`)) return;
      try {
        await api(`/api/firmware?vendor=${encodeURIComponent(btn.dataset.vendor)}&filename=${encodeURIComponent(btn.dataset.filename)}`, {
          method: "DELETE",
        });
        toast("Удалено");
        loadFirmware();
      } catch (e) {
        toast(e.message, true);
      }
    });
  });
}

document.getElementById("fw-upload-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const vendor = document.getElementById("fw-vendor").value;
  const fileInput = document.getElementById("fw-file");
  const file = fileInput.files[0];
  const statusEl = document.getElementById("fw-upload-status");
  const btn = document.getElementById("fw-upload-btn");
  if (!file) return toast("Выбери файл", true);

  const fd = new FormData();
  fd.append("vendor", vendor);
  fd.append("file", file);

  btn.disabled = true;
  btn.textContent = "Загружаю…";
  statusEl.textContent = "";
  try {
    const res = await fetch("/api/firmware/upload", {
      method: "POST",
      headers: { "X-API-Key": apiKey() },
      body: fd,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `HTTP ${res.status}`);
    }
    fileInput.value = "";
    toast("Образ загружен");
    loadFirmware();
  } catch (e) {
    statusEl.innerHTML = `<span style="color:var(--crit)">${escapeHtml(e.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Загрузить";
  }
});

function onKeySaved() {
  loadFirmware();
}

loadFirmware();
