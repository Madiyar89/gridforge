"""Шифрование пароля внутри Probe.params/Action.config — закрывает
известный пробел, задокументированный в README с самого появления
ssh_command (Probe.params.password/Action.config.password раньше лежали
в SQLite обычным JSON, без шифрования, в отличие от Ansible Vault в
NetOpsHub).

Ключ — файл `data/secret.key` (Fernet, 32 байта), создаётся один раз при
первом обращении, права 0600. Не переиспользует ApiKey-таблицу и не
хранит ключ в самой БД — иначе шифрование секретов зависело бы от той же
БД, которую защищает (тот же принцип, что TENANT_DB_ENC_KEY в соседнем
проекте fixed_phonebook — ключ шифрования БД живёт вне самой БД)."""

from __future__ import annotations

from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "secret.key"
_fernet: Fernet | None = None

SECRET_MARKER = "enc:"  # префикс, отличающий уже зашифрованное значение от старого plaintext


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        key = _KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        _KEY_PATH.write_bytes(key)
        _KEY_PATH.chmod(0o600)
    _fernet = Fernet(key)
    return _fernet


def encrypt_secret(plain: str) -> str:
    token = _get_fernet().encrypt(plain.encode("utf-8")).decode("ascii")
    return SECRET_MARKER + token


def decrypt_secret(value: str) -> str:
    """Принимает и зашифрованные (`enc:...`), и уже расшифрованные строки
    без маркера — на случай данных, заведённых до появления шифрования
    (не роняем существующие Probe/Action, просто не защищаем их задним
    числом)."""
    if not value.startswith(SECRET_MARKER):
        return value
    token = value[len(SECRET_MARKER):]
    try:
        return _get_fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return value  # ключ сменился/данные повреждены — не роняем вызывающий код молча теряя пароль, а даём ошибке SSH-подключения проявиться естественно
