import logging
import stat
import sys

import pytest
from cryptography.fernet import Fernet

from app import secrets_crypto
from app.models import Channel, ChannelKind, Credential, Integration


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


def _encrypt_with(fernet: Fernet, plaintext: str) -> str:
    return secrets_crypto.SECRET_MARKER + fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


class TestRotateSecrets:
    """Ротация ключа (аудит: data/secret.key создавался один раз и никогда
    не менялся) — rotate_secrets перешифровывает все известные секреты со
    старого Fernet-ключа на новый, см. секцию "Ротация ключа шифрования" в
    secrets_crypto.py."""

    def test_rotates_credential_integration_and_channel_fields(self, db):
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()
        old_fernet = Fernet(old_key)

        cred = Credential(username="admin", password=_encrypt_with(old_fernet, "hunter2"))
        integration = Integration(
            key="zabbix", url="http://zabbix.local", api_token=_encrypt_with(old_fernet, "zbx-token-abc")
        )
        channel = Channel(
            kind=ChannelKind.webhook,
            config={
                "url": _encrypt_with(old_fernet, "https://hooks.example/T00/B00/xyz"),
                "note": "not a secret field, must be left alone",
            },
        )
        db.add_all([cred, integration, channel])
        db.commit()
        db.refresh(cred)
        db.refresh(integration)
        db.refresh(channel)

        cred_ciphertext_before = cred.password
        token_ciphertext_before = integration.api_token
        channel_ciphertext_before = channel.config["url"]

        counts = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)

        assert counts == {
            "total_fields": 3,
            "migrated": 3,
            "already_current": 0,
            "plaintext_skipped": 0,
            "unreadable": 0,
        }

        db.refresh(cred)
        db.refresh(integration)
        db.refresh(channel)

        # Шифротекст реально изменился (не просто "оставлено как было") —
        # доказывает, что поле было ПЕРЕШИФРОВАНО, а не пропущено.
        assert cred.password != cred_ciphertext_before
        assert integration.api_token != token_ciphertext_before
        assert channel.config["url"] != channel_ciphertext_before
        # Не относящееся к секретам поле config не тронуто.
        assert channel.config["note"] == "not a secret field, must be left alone"

        # Новый ключ действительно расшифровывает — через decrypt_secret(),
        # как это делает вся остальная кодовая база, не только напрямую
        # через Fernet(new_key).
        new_fernet = Fernet(new_key)
        assert new_fernet.decrypt(cred.password[len(secrets_crypto.SECRET_MARKER):].encode()) == b"hunter2"
        assert (
            new_fernet.decrypt(integration.api_token[len(secrets_crypto.SECRET_MARKER):].encode())
            == b"zbx-token-abc"
        )
        assert (
            new_fernet.decrypt(channel.config["url"][len(secrets_crypto.SECRET_MARKER):].encode())
            == b"https://hooks.example/T00/B00/xyz"
        )

    def test_rotate_secrets_decryptable_via_decrypt_secret_with_new_key(self, db, monkeypatch):
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()
        old_fernet = Fernet(old_key)

        cred = Credential(username="admin", password=_encrypt_with(old_fernet, "hunter2"))
        db.add(cred)
        db.commit()

        secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)
        db.refresh(cred)

        # decrypt_secret() (использует ГЛОБАЛЬНЫЙ кэшированный ключ, как в
        # реальном приложении) должен читать перешифрованное значение,
        # если процесс настроен на новый ключ.
        monkeypatch.setattr(secrets_crypto, "_fernet", Fernet(new_key))
        assert secrets_crypto.decrypt_secret(cred.password) == "hunter2"

    def test_rotate_secrets_is_idempotent(self, db):
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()
        old_fernet = Fernet(old_key)

        cred = Credential(username="admin", password=_encrypt_with(old_fernet, "hunter2"))
        db.add(cred)
        db.commit()

        first = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)
        db.refresh(cred)
        value_after_first_run = cred.password

        # Повторный прогон (напр. ретрай после сбоя) с теми же ключами:
        # ничего не должно перешифровываться заново, значение остаётся
        # читаемым, не портится "двойным" шифрованием.
        second = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)
        db.refresh(cred)

        assert first["migrated"] == 1
        assert first["already_current"] == 0
        assert second["migrated"] == 0
        assert second["already_current"] == 1
        assert cred.password == value_after_first_run

        new_fernet = Fernet(new_key)
        assert (
            new_fernet.decrypt(cred.password[len(secrets_crypto.SECRET_MARKER):].encode())
            == b"hunter2"
        )

    def test_rotate_secrets_with_no_secrets_in_db_is_a_clean_no_op(self, db):
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        counts = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)

        assert counts == {
            "total_fields": 0,
            "migrated": 0,
            "already_current": 0,
            "plaintext_skipped": 0,
            "unreadable": 0,
        }

    def test_rotate_secrets_leaves_legacy_plaintext_untouched(self, db):
        # Данные, заведённые до появления шифрования (без enc:-маркера) —
        # ротация не должна их шифровать задним числом, тот же принцип,
        # что и у decrypt_secret.
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        cred = Credential(username="admin", password="plain-old-password")
        db.add(cred)
        db.commit()

        counts = secrets_crypto.rotate_secrets(db, new_key=new_key, old_key=old_key)
        db.refresh(cred)

        assert counts["plaintext_skipped"] == 1
        assert counts["migrated"] == 0
        assert cred.password == "plain-old-password"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-права доступа проверяются только на Linux/Docker")
class TestArchiveAndReplaceKey:
    """archive_and_replace_key — второй шаг ротации (после rotate_secrets):
    старый файл ключа архивируется (переименовывается), НЕ удаляется, новый
    пишется на его место с правами 0600."""

    def test_old_key_archived_new_key_written_with_correct_permissions(self, tmp_path, monkeypatch):
        key_path = tmp_path / "secret.key"
        old_key = Fernet.generate_key()
        key_path.write_bytes(old_key)
        key_path.chmod(0o600)

        monkeypatch.setattr(secrets_crypto, "_KEY_PATH", key_path)
        monkeypatch.setattr(secrets_crypto, "_fernet", Fernet(old_key))

        new_key = Fernet.generate_key()
        archived_path = secrets_crypto.archive_and_replace_key(new_key)

        # Старый ключ не удалён — переименован, содержимое не тронуто.
        assert archived_path.exists()
        assert archived_path != key_path
        assert archived_path.read_bytes() == old_key
        assert "rotated-" in archived_path.name

        # Новый ключ теперь лежит по исходному пути с правильными правами.
        assert key_path.read_bytes() == new_key
        assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

        # Кэш ключа в памяти сброшен — следующий _get_fernet() подхватит
        # новый файл, а не продолжит отдавать старый Fernet-объект.
        assert secrets_crypto._fernet is None

    def test_raises_if_no_key_to_archive(self, tmp_path, monkeypatch):
        monkeypatch.setattr(secrets_crypto, "_KEY_PATH", tmp_path / "does-not-exist.key")

        with pytest.raises(FileNotFoundError):
            secrets_crypto.archive_and_replace_key(Fernet.generate_key())
