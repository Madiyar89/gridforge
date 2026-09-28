"""Trust-on-first-use (TOFU) проверка SSH host key — см. app/ssh_client.py.

evaluate_host_key() — чистая функция сравнения, без сети и без БД,
поэтому тестируется напрямую без реального SSH-сервера. Остальной код
(_TofuSSHClient.validate_host_public_key, open_ssh_connection) — тонкие
обёртки над ней вокруг API asyncssh, здесь не переисследуются."""

from app.ssh_client import evaluate_host_key


def test_first_connect_stores_fingerprint():
    """Fingerprint ещё не сохранён — разрешить и пометить, что нужно
    запомнить presented_fingerprint."""
    decision = evaluate_host_key(None, "SHA256:aaaa")
    assert decision.allow is True
    assert decision.is_new is True
    assert decision.fingerprint == "SHA256:aaaa"
    assert decision.error is None


def test_first_connect_stores_fingerprint_when_empty_string():
    """Пустая строка (не только None) тоже считается «ещё не сохранён» —
    на случай, если колонка когда-то была пустой строкой, а не NULL."""
    decision = evaluate_host_key("", "SHA256:aaaa")
    assert decision.allow is True
    assert decision.is_new is True


def test_matching_fingerprint_allows_without_rewrite():
    """Совпадает с сохранённым — разрешить, но НЕ помечать как новый (иначе
    каждое подключение писало бы в БД без необходимости)."""
    decision = evaluate_host_key("SHA256:aaaa", "SHA256:aaaa")
    assert decision.allow is True
    assert decision.is_new is False
    assert decision.error is None


def test_mismatched_fingerprint_rejects_with_clear_message():
    """Несовпадение — отклонить, сообщение объясняет, что произошло, и
    что делать в легитимном случае замены устройства."""
    decision = evaluate_host_key("SHA256:aaaa", "SHA256:bbbb")
    assert decision.allow is False
    assert decision.is_new is False
    assert decision.error is not None
    assert "MITM" in decision.error
    assert "Настройки" in decision.error


def test_mismatch_does_not_silently_allow():
    """Регрессия на конкретно ту ошибку, которую TOFU должен исключать:
    несовпадение никогда не должно возвращать allow=True."""
    for stored, presented in [("SHA256:x", "SHA256:y"), ("SHA256:1", "SHA256:2")]:
        assert evaluate_host_key(stored, presented).allow is False
