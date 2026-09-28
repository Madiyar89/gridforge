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
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

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


# --- Перечисление всех мест хранения секретов ------------------------------
#
# Единая точка "где в БД лежит зашифрованный (или потенциально ещё не
# зашифрованный legacy-plaintext) секрет" — раньше это знание было размазано:
# collect_known_secrets() ниже знало только про Credential/Integration/
# Channel, а Probe.params (password/auth_password/priv_password/community),
# Action.config.password, LdapConnection.password и DomainScanCredentialSet.
# password шифровались (см. main.py/ldap_engine.py/domain_scan_engine.py), но
# нигде не перечислялись централизованно. Для ротации ключа (см.
# rotate_secrets ниже) пропустить любое из этих полей означало бы оставить
# его тихо нечитаемым после смены ключа — поэтому здесь заведён ПОЛНЫЙ
# список, а collect_known_secrets() теперь построен на нём же, а не на своей
# отдельной, более узкой копии (заодно чинит попутно найденный баг: раньше
# для Channel.config значения добавлялись в набор "известных секретов" БЕЗ
# decrypt_secret — то есть в редактировании ActionRun.output сравнивался
# шифротекст `enc:...`, который физически не может встретиться в открытом
# stdout команды; функционально редактирование токенов каналов не работало).

PROBE_SECRET_PARAM_FIELDS = ("password", "auth_password", "priv_password", "community")
ACTION_SECRET_CONFIG_FIELDS = ("password",)
# Дублирует signal.CHANNEL_SECRET_FIELDS — не импортируется оттуда напрямую
# (даже лениво, внутри функции), чтобы не завязывать secrets_crypto.py,
# исторически не знающий о models.py/бизнес-модулях, на app.signal тоже;
# набор полей канала стабилен (webhook/telegram/apprise, см. signal.py) и
# меняется тем же кодревью, что и сам этот список.
CHANNEL_SECRET_CONFIG_FIELDS = ("bot_token", "url")


class _SecretField:
    """Одно место хранения секрета: `label` — для логов, `get()` возвращает
    текущее сырое значение (с `enc:`-маркером или legacy-plaintext без
    него), `set(raw)` записывает новое сырое значение обратно в объект
    SQLAlchemy (для JSON-полей — пересозданием словаря, чтобы SQLAlchemy
    гарантированно увидел изменение и включил объект в UPDATE — простая
    мутация словаря на месте dirty-tracking не гарантирует)."""

    __slots__ = ("label", "get", "set")

    def __init__(self, label, get, set):
        self.label = label
        self.get = get
        self.set = set


def _attr_field(label: str, obj, attr: str) -> _SecretField:
    return _SecretField(label, lambda: getattr(obj, attr), lambda v: setattr(obj, attr, v))


def _dict_field(label: str, obj, attr: str, key: str) -> _SecretField:
    def get():
        return (getattr(obj, attr) or {}).get(key)

    def set_(value):
        updated = dict(getattr(obj, attr) or {})
        updated[key] = value
        setattr(obj, attr, updated)

    return _SecretField(label, get, set_)


def iter_secret_fields(db):
    """Генератор `_SecretField` по ВСЕМ местам в БД, где GridForge хранит
    Fernet-шифруемый секрет. Используется и `collect_known_secrets` (только
    чтение/расшифровка), и `rotate_secrets` (чтение + перезапись) — общая
    точка правды, чтобы список таблиц/полей не расходился между двумя
    задачами.

    Импорт моделей — внутри функции (см. исходный докстринг
    collect_known_secrets ниже): secrets_crypto.py исторически не зависит
    от models.py на уровне модуля."""
    from app.models import (
        Action,
        Channel,
        Credential,
        DomainScanCredentialSet,
        Integration,
        LdapConnection,
        Probe,
    )

    for cred in db.query(Credential).all():
        if cred.password:
            yield _attr_field("Credential.password", cred, "password")

    for integration in db.query(Integration).all():
        if integration.api_token:
            yield _attr_field("Integration.api_token", integration, "api_token")

    for ldap in db.query(LdapConnection).all():
        if ldap.password:
            yield _attr_field("LdapConnection.password", ldap, "password")

    for cred_set in db.query(DomainScanCredentialSet).all():
        if cred_set.password:
            yield _attr_field("DomainScanCredentialSet.password", cred_set, "password")

    for channel in db.query(Channel).all():
        config = channel.config or {}
        for field in CHANNEL_SECRET_CONFIG_FIELDS:
            if config.get(field):
                yield _dict_field(f"Channel[{channel.id}].config.{field}", channel, "config", field)

    for probe in db.query(Probe).all():
        params = probe.params or {}
        for field in PROBE_SECRET_PARAM_FIELDS:
            if params.get(field):
                yield _dict_field(f"Probe[{probe.id}].params.{field}", probe, "params", field)

    for action in db.query(Action).all():
        config = action.config or {}
        for field in ACTION_SECRET_CONFIG_FIELDS:
            if config.get(field):
                yield _dict_field(f"Action[{action.id}].config.{field}", action, "config", field)


def collect_known_secrets(db) -> set[str]:
    """Все расшифрованные секреты, которые GridForge сам хранит в этом
    инстансе — используется ТОЛЬКО в момент сохранения ActionRun.output
    (см. actions_engine.py), не на горячем пути опроса: вызывается один раз
    на каждое реально выполненное (не skipped) срабатывание Action. Полный
    скан нескольких небольших таблиц + расшифровка Fernet — приемлемая
    цена для парка в десятки-сотни узлов и редких срабатываний Action; не
    оптимизируем заранее для нагрузки, которой у этого проекта нет."""
    secrets = {decrypt_secret(field.get()) for field in iter_secret_fields(db)}
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


# --- Ротация ключа шифрования -----------------------------------------------
#
# Аудит нашёл: data/secret.key создаётся один раз (_get_fernet выше) и живёт
# вечно, без механизма смены — низкая приоритетность для маленького
# внутреннего инструмента (нет требования комплаенса на периодическую
# ротацию), но по прямому запросу владельца всё равно реализовано.
#
# Точка входа для админа — deploy/rotate_secret_key.py (тот же паттерн
# одноразовой ручной утилиты, что deploy/import_from_netopshub.py), НЕ HTTP-
# эндпоинт: смена ключа шифрования — операция, требующая реального доступа
# к серверу/shell, не то, что должно быть доступно случайным вызовом API
# (тот же принцип, что и у прочих чувствительных одноразовых операций в
# этом проекте).
#
# MultiFernet([new, old]) — механизм ротации, для которого сам Fernet и
# создавался: encrypt() всегда через ПЕРВЫЙ ключ списка (новый), decrypt()
# перебирает все (новый, потом старый) — то есть на время самой операции
# ротации значение читаемо и старым, и новым ключом одновременно, что и
# делает шаг "перешифровать всё" безопасным для повтора/восстановления
# после сбоя.
def rotate_secrets(db, new_key: bytes, old_key: bytes) -> dict[str, int]:
    """Перешифровывает ВСЕ известные секреты (см. iter_secret_fields выше)
    со старого ключа на новый и коммитит одной транзакцией.

    Идемпотентность/устойчивость к сбою в середине операции: для каждого
    поля сначала пробуем расшифровать значение ТОЛЬКО новым ключом — успех
    значит поле уже перешифровано прошлым (возможно прерванным) запуском,
    трогать не нужно. Это и даёт безопасный повторный запуск без двойного
    шифрования: не нужно отдельно хранить "под каким ключом сейчас поле X",
    MultiFernet.decrypt (соответственно — ручная проверка "новым, потом
    старым" ниже) сам разбирается, каким из двух ключей значение читается.

    Если весь скан прошёл без исключений — одна БД-транзакция коммитится
    в конце (единый db.commit()), не построчно: либо все успешно
    перешифрованные в этом запуске поля попадают в БД разом, либо (при
    падении процесса до commit) ни одно — транзакция СУБД откатывается
    сама при переподключении, и повторный запуск начинает набор "уже
    перешифровано" с нуля, но безопасно (снова увидит их как
    незашифрованные новым ключом и перешифрует)."""
    new_fernet = Fernet(new_key)
    old_fernet = Fernet(old_key)
    multi = MultiFernet([new_fernet, old_fernet])

    counts = {
        "total_fields": 0,
        "migrated": 0,
        "already_current": 0,
        "plaintext_skipped": 0,
        "unreadable": 0,
    }

    for field in iter_secret_fields(db):
        counts["total_fields"] += 1
        raw = field.get()
        if not raw:
            continue
        if not raw.startswith(SECRET_MARKER):
            # Legacy-plaintext, заведённый до появления шифрования (см.
            # decrypt_secret) — ротации нечего перешифровывать, тот же
            # принцип "не защищаем задним числом", что и у decrypt_secret.
            counts["plaintext_skipped"] += 1
            continue

        token = raw[len(SECRET_MARKER):].encode("ascii")

        try:
            new_fernet.decrypt(token)
            # Уже читается новым ключом — либо этот прогон запущен повторно
            # после того как поле уже перешифровано, либо (маловероятно)
            # оба ключа совпали. Не трогаем: перезапись дала бы новый
            # шифротекст без изменения смысла, лишний шум в логах/diff БД.
            counts["already_current"] += 1
            continue
        except InvalidToken:
            pass

        try:
            plaintext = multi.decrypt(token)
        except InvalidToken:
            # Не читается ни новым, ни старым ключом — уже было повреждено/
            # зашифровано неизвестным третьим ключом ДО ротации (decrypt_
            # secret в проде тоже не смог бы это прочитать). Ротация не
            # виновата и не может это починить — оставляем как есть и
            # громко логируем, чтобы админ разобрался руками.
            logger.error(
                "rotate_secrets: %s не расшифровывается ни новым, ни старым ключом — "
                "оставлено без изменений, требует ручной проверки",
                field.label,
            )
            counts["unreadable"] += 1
            continue

        field.set(SECRET_MARKER + new_fernet.encrypt(plaintext).decode("ascii"))
        counts["migrated"] += 1

    db.commit()

    logger.info(
        "rotate_secrets завершена: %d полей всего, %d перешифровано, %d уже под новым ключом, "
        "%d legacy-plaintext (не тронуты), %d нечитаемых ни одним ключом",
        counts["total_fields"],
        counts["migrated"],
        counts["already_current"],
        counts["plaintext_skipped"],
        counts["unreadable"],
    )
    return counts


def archive_and_replace_key(new_key: bytes) -> Path:
    """Архивирует текущий data/secret.key (переименовывает, НЕ удаляет) и
    записывает `new_key` на его место с правами 0600. Вызывать ТОЛЬКО
    ПОСЛЕ успешного rotate_secrets() — иначе секреты в БД останутся
    зашифрованы старым ключом, а файл ключа уже станет новым, и
    приложение перестанет их расшифровывать (см. deploy/rotate_secret_key.py).

    Возвращает путь к архивной копии старого ключа. Она не удаляется
    автоматически этой функцией — сознательно: если после ротации
    что-то пойдёт не так, у админа должна остаться возможность
    свериться со старым ключом или откатиться, удалить архивную копию
    руками можно позже, когда ротация подтверждена рабочей."""
    if not _KEY_PATH.exists():
        raise FileNotFoundError(f"{_KEY_PATH} не существует — нечего архивировать")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archived_path = _KEY_PATH.with_name(f"{_KEY_PATH.name}.rotated-{timestamp}")
    _KEY_PATH.rename(archived_path)
    _KEY_PATH.write_bytes(new_key)
    if sys.platform != "win32":
        _KEY_PATH.chmod(0o600)

    global _fernet
    _fernet = None  # сброс кэша в памяти — следующий _get_fernet() перечитает новый файл

    return archived_path
