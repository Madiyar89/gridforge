// SSH-консоль — xterm.js в браузере, WebSocket-мост к app/console_ws.py.

const term = new Terminal({
  cursorBlink: true,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  fontSize: 13,
  theme: { background: "#000000" },
});
term.open(document.getElementById("term"));
term.write("Подключись слева, чтобы начать сессию.\r\n");

let ws = null;

function setStatus(text, cls) {
  const el = document.getElementById("c-status");
  el.textContent = text;
  el.className = "console-status" + (cls ? " " + cls : "");
}

async function loadNodePicker() {
  const select = document.getElementById("c-node");
  try {
    const nodes = sortNodesNatural(await api("/api/nodes"));
    select.innerHTML = `<option value="">выбери узел…</option>` + nodes.map((n) => `<option value="${n.id}">${escapeHtml(n.name)} (${escapeHtml(n.address)})</option>`).join("");
  } catch (e) {
    select.innerHTML = `<option value="">${emptyOrError(e)}</option>`;
  }
}

document.getElementById("c-connect").addEventListener("click", () => {
  const nodeId = document.getElementById("c-node").value;
  const username = document.getElementById("c-user").value.trim();
  const keyPath = document.getElementById("c-key").value.trim();
  const password = document.getElementById("c-pass").value;
  const port = Number(document.getElementById("c-port").value) || 22;
  if (!nodeId) return toast("Выбери узел", true);
  if (!username) return toast("Укажи логин", true);
  if (!keyPath && !password) return toast("Укажи ключ или пароль", true);

  if (ws) {
    ws.close();
    ws = null;
  }
  term.reset();
  setStatus("подключение…", "");

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws/console`);

  ws.addEventListener("open", () => {
    ws.send(
      JSON.stringify({
        type: "connect",
        api_key: apiKey(),
        node_id: Number(nodeId),
        username,
        key_path: keyPath || undefined,
        password: password || undefined,
        port,
        cols: term.cols,
        rows: term.rows,
      })
    );
  });

  ws.addEventListener("message", (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === "connected") {
      setStatus("подключено", "live");
      term.focus();
    } else if (msg.type === "data") {
      term.write(msg.data);
    } else if (msg.type === "error") {
      setStatus("ошибка: " + msg.message, "err");
      toast(msg.message, true);
    } else if (msg.type === "closed") {
      setStatus("сессия закрыта", "");
    }
  });

  ws.addEventListener("close", () => {
    setStatus("отключено", "");
  });

  ws.addEventListener("error", () => {
    setStatus("ошибка соединения", "err");
  });
});

term.onData((data) => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "data", data }));
  }
});

term.onResize(({ cols, rows }) => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({ type: "resize", cols, rows }));
  }
});

function onKeySaved() {
  loadNodePicker();
}

loadNodePicker();
