// Страница входа. Намеренно не тянет common.js: там код, рассчитанный на
// уже авторизованного пользователя (обновление роли, навигация), а здесь
// ещё ничего этого нет.

const form = document.getElementById("login-form");
const errorBox = document.getElementById("login-error");
const submitBtn = document.getElementById("login-submit");

fetch("/api/oidc-status")
  .then((r) => r.json())
  .then((data) => {
    if (data.enabled) document.getElementById("oidc-block").style.display = "";
  })
  .catch(() => {});

document.getElementById("oidc-login-btn").addEventListener("click", () => {
  window.location.href = "/auth/oidc/login";
});

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  errorBox.textContent = "";
  submitBtn.disabled = true;
  submitBtn.textContent = "Проверяю…";

  try {
    const resp = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("login-username").value,
        password: document.getElementById("login-password").value,
      }),
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.detail || "Не удалось войти");
    }
    // Кука установлена сервером (httponly — отсюда её не видно и не надо).
    window.location.href = "/";
  } catch (e) {
    errorBox.textContent = e.message;
    document.getElementById("login-password").value = "";
    document.getElementById("login-password").focus();
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Войти";
  }
});
