// «Спроси про сеть» — read-only ИИ-отчёт (app/ask_engine.py).

async function runAsk(question) {
  const body = document.getElementById("ask-body");
  const btn = document.getElementById("ask-submit");
  if (!question.trim()) return toast("Введи вопрос", true);
  btn.disabled = true;
  btn.textContent = "Думаю…";
  body.innerHTML = `<div class="empty">Запрашиваю…</div>`;
  try {
    const r = await api("/api/ask", { method: "POST", body: JSON.stringify({ question }) });
    const queriesHtml = r.queries && r.queries.length
      ? `<details class="ask-queries"><summary>Выполненные запросы (${r.queries.length})</summary>${r.queries
          .map((q) => `<div class="ask-query-row">${escapeHtml(q.sql)} — ${q.row_count} строк</div>`)
          .join("")}</details>`
      : `<div class="ask-queries">Модель ответила без обращения к БД</div>`;
    body.innerHTML = `<div class="ask-answer">${escapeHtml(r.answer)}</div>${queriesHtml}`;
  } catch (e) {
    body.innerHTML = `<div class="empty">${emptyOrError(e)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Спросить";
  }
}

document.getElementById("ask-submit").addEventListener("click", () => {
  runAsk(document.getElementById("ask-question").value);
});
document.getElementById("ask-question").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runAsk(document.getElementById("ask-question").value);
});
document.querySelectorAll(".ask-example").forEach((el) => {
  el.addEventListener("click", () => {
    document.getElementById("ask-question").value = el.textContent;
    runAsk(el.textContent);
  });
});

function onKeySaved() {}
