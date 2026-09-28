// SSH-консоль — xterm.js в браузере, WebSocket-мост к app/console_ws.py.

// Классический зелёный терминал на чёрном (по запросу пользователя,
// 2026-09-24) + сетка покрупнее — панель теперь на всю страницу
// (см. #term-wrap в console.html), без addon для авто-fit имеющийся
// xterm.js не подстраивает cols/rows под контейнер сам, поэтому просто
// берём щедрый фиксированный размер, а не подгоняем в пиксель.
const term = new Terminal({
  cursorBlink: true,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
  fontSize: 13,
  cols: 200,
  rows: 46,
  theme: {
    background: "#000000",
    foreground: "#33ff66",
    cursor: "#33ff66",
    cursorAccent: "#000000",
    selectionBackground: "#1f6b3a",
    black: "#000000",
    green: "#33ff66",
    brightGreen: "#7dffa3",
  },
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
  // username/пароль/ключ можно не указывать — тогда сервер подставит
  // центральную учётку узла (Настройки → Учётки), см. main.py/console_ws.py.

  if (ws) {
    ws.close();
    ws = null;
  }
  term.reset();
  setStatus("подключение…", "");

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws/console`);

  ws.addEventListener("open", () => {
    // Без api_key — браузер сам прикладывает куку входа (та же
    // gridforge_session, что и остальной сайт) при WebSocket-хендшейке,
    // сервер проверяет её в handle_console (см. console_ws.py). api_key в
    // теле сообщения остаётся рабочим отдельно для не-браузерных клиентов.
    ws.send(
      JSON.stringify({
        type: "connect",
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
