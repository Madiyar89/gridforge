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

import logging
import stat
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("gridforge.secrets_crypto")

_KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "secret.key"
_fernet: Fernet | None = None

SECRET_MARKER = "enc:"  # префикс, отличающий уже зашифрованное значение от старого plaintext

_EXPECTED_MODE = 0o600


def _enforce_key_permissions(path: Path) -> None:
    """Проверяет права на файл ключа и принудительно возвращает их к 0600.

    Ключ шифрует все секреты приложения (SSH-пароли, API-токены, bind-пароль
    LDAP и т.д.), поэтому если права расширились — например файл
    восстановлен из бэкапа с другим umask или скопирован вручную без
    сохранения прав, — тихо продолжать работу с ним небезопасно. Правим
    автоматически (не просто предупреждаем): это собственный служебный
    файл приложения, которым кроме нас никто не управляет, так что молчаливое
    "подождать, пока админ заметит warning в логах" оставляло бы ключ
    доступным на чтение дольше, чем нужно. На Windows (вне Docker,
    локальная разработка) os.chmod не имеет смысла — POSIX-биты прав там
    не поддерживаются, поэтому проверку пропускаем."""
    if sys.platform == "win32":
        return
    current_mode = stat.S_IMODE(path.stat().st_mode)
    if current_mode != _EXPECTED_MODE:
        logger.warning(
            "%s had permissions %o, expected %o — corrected automatically. "
            "If this file was restored from a backup or copied manually, "
            "verify no other process/user can read it.",
            path,
            current_mode,
            _EXPECTED_MODE,
        )
        path.chmod(_EXPECTED_MODE)


def _get_fernet() -> Fernet:
    global _fernet
    if _fernet is not None:
        return _fernet
    _KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_PATH.exists():
        _enforce_key_permissions(_KEY_PATH)
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


# --- Редактирование известных секретов в выводе Action (аудит: ActionRun.
# output хранит сырой stdout SSH-команды, которую пишет админ; если
# команда печатает секрет (напр. `echo $CRED_PASSWORD` или дамп конфига
# с паролем), он попадает в БД открытым текстом — а читать ActionRun
# доступно ЛЮБОМУ действующему API-ключу (api_read, не только admin, см.
# main.py: GET /api/incidents/{id}/action-runs). Общего решения "найти
# любой секрет в произвольном выводе" не существует, поэтому подход
# сознательно ограничен: ищем в выводе ТОЛЬКО значения, которые сам
# GridForge уже хранит как секрет (Credential.password, Integration.
# api_token, значения в Channel.config) — точное совпадение, без
# эвристик по "похоже на секрет". Не ловит секреты, о которых GridForge
# не знает (сторонний API-ключ, зашитый в скрипт) — это фундаментально
# нерешаемый в общем виде случай, вне scope этой меры. ---

REDACTED_PLACEHOLDER = "***REDACTED (совпадает с сохранённым секретом)***"

# Секреты короче этого порога не редактируются: короткая строка (напр.
# пароль "abc") слишком часто случайно совпадает с обычными фрагментами
# вывода команды (частями путей, слов, чисел), и агрессивная замена дала
# бы много ложных срабатываний, искажающих легитимный вывод. 8 символов —
# типичный нижний порог "непустого пароля", ниже которого точность
# сопоставления быстро падает; секреты короче этого порога остаются
# нередактированными в ActionRun.output — известное и осознанное
# ограничение этого подхода, не баг.
MIN_REDACTABLE_SECRET_LENGTH = 8


def collect_known_secrets(db) -> set[str]:
    """Все расшифрованные секреты, которые GridForge сам хранит в этом
    инстансе (Credential.password, Integration.api_token, значения в
    Channel.config — bot_token/url и т.п.) — используется ТОЛЬКО в
    момент сохранения ActionRun.output (см. actions_engine.py), не на
    горячем пути опроса: вызывается один раз на каждое реально
    выполненное (не skipped) срабатывание Action. Полный скан трёх
    небольших таблиц + расшифровка Fernet — приемлемая цена для парка в
    десятки-сотни узлов и редких срабатываний Action; не оптимизируем
    заранее для нагрузки, которой у этого проекта нет.

    Импорт моделей — внутри функции, а не на уровне модуля: secrets_
    crypto.py исторически не зависит от models.py, держим эту границу и
    здесь, чтобы не вводить обязательную загрузку SQLAlchemy-моделей при
    простом encrypt/decrypt_secret."""
    from app.models import Channel, Credential, Integration

    secrets: set[str] = set()

    for cred in db.query(Credential).all():
        if cred.password:
            secrets.add(decrypt_secret(cred.password))

    for integration in db.query(Integration).all():
        if integration.api_token:
            secrets.add(decrypt_secret(integration.api_token))

    for channel in db.query(Channel).all():
        for value in (channel.config or {}).values():
            if isinstance(value, str) and value:
                secrets.add(value)

    return {s for s in secrets if s and len(s) >= MIN_REDACTABLE_SECRET_LENGTH}


def redact_known_secrets(text: str | None, known_secrets: set[str]) -> str | None:
    """Заменяет в `text` все вхождения любого значения из `known_secrets`
    на REDACTED_PLACEHOLDER. Точное совпадение подстроки (не regex, не
    эвристика по "форме" секрета) — см. комментарий выше о том, почему
    это осознанно узкая мера, а не общий детектор секретов."""
    if not text or not known_secrets:
        return text
    for secret in known_secrets:
        if secret and secret in text:
            text = text.replace(secret, REDACTED_PLACEHOLDER)
    return text
