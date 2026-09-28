import logging
import stat
import sys

import pytest
from cryptography.fernet import Fernet

from app import secrets_crypto


def test_encrypt_decrypt_roundtrip():
    encrypted = secrets_crypto.encrypt_secret("my-password-123")
    assert encrypted.startswith(secrets_crypto.SECRET_MARKER)
    assert encrypted != "my-password-123"
    assert secrets_crypto.decrypt_secret(encrypted) == "my-password-123"


def test_decrypt_passthrough_for_legacy_plaintext():
    # Данные, заведённые до появления шифрования — без маркера enc:,
    # decrypt_secret не должен их трогать/ронять.
    assert secrets_crypto.decrypt_secret("plain-old-password") == "plain-old-password"


def test_decrypt_invalid_token_does_not_raise():
    # Ключ сменился или данные повреждены — decrypt_secret должен молча
    # вернуть исходную (нерасшифрованную) строку, не поднимать исключение,
    # чтобы ошибка проявилась естественно на уровне SSH/SNMP-подключения.
    fake = secrets_crypto.SECRET_MARKER + "not-a-real-fernet-token"
    result = secrets_crypto.decrypt_secret(fake)
    assert result == fake


def test_different_secrets_produce_different_ciphertext():
    a = secrets_crypto.encrypt_secret("secret-a")
    b = secrets_crypto.encrypt_secret("secret-b")
    assert a != b


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-права доступа проверяются только на Linux/Docker")
class TestKeyPermissionsEnforced:
    """Аудит нашёл: права на data/secret.key проверялись/выставлялись только
    при СОЗДАНИИ файла, но никогда не перепроверялись при чтении уже
    существующего ключа (например после восстановления из бэкапа с другим
    umask или ручного cp). _enforce_key_permissions должна и чинить права,
    и явно предупреждать в логе."""

    def test_correct_permissions_left_untouched_no_warning(self, tmp_path, caplog):
        key_path = tmp_path / "secret.key"
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o600)

        with caplog.at_level(logging.WARNING, logger="gridforge.secrets_crypto"):
            secrets_crypto._enforce_key_permissions(key_path)

        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert caplog.records == []

    def test_wrong_permissions_corrected_and_warned(self, tmp_path, caplog):
        key_path = tmp_path / "secret.key"
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o644)

        with caplog.at_level(logging.WARNING, logger="gridforge.secrets_crypto"):
            secrets_crypto._enforce_key_permissions(key_path)

        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert any("corrected automatically" in r.message for r in caplog.records)
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    def test_get_fernet_enforces_permissions_on_existing_key(self, tmp_path, monkeypatch, caplog):
        # Сквозная проверка: _get_fernet() при чтении УЖЕ существующего
        # ключа (не только при первом создании) должен подтягивать
        # _enforce_key_permissions.
        key_path = tmp_path / "secret.key"
        key_path.write_bytes(Fernet.generate_key())
        key_path.chmod(0o644)

        monkeypatch.setattr(secrets_crypto, "_KEY_PATH", key_path)
        monkeypatch.setattr(secrets_crypto, "_fernet", None)

        with caplog.at_level(logging.WARNING, logger="gridforge.secrets_crypto"):
            secrets_crypto._get_fernet()

        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
        assert any(r.levelno == logging.WARNING for r in caplog.records)
