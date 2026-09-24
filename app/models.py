"""Схема данных GridForge.

Терминология сознательно своя, не калька с Zabbix (hosts/items/triggers/
events) и не переиспользование имён из NetOpsHub (Device/Alert) — см.
docs/rewrite-ledger в NetOpsHub-project про риск "просто переименовали":

    Node      — опрашиваемый узел (устройство/сервер/сервис)
    Probe     — сконфигурированная проверка на узле (не "item")
    Sample    — один результат проверки (не "history"/"history_uint")
    Watch     — условие над выборкой последних Sample (не "trigger")
    Incident  — открытое/закрытое совпадение Watch (не "event"/"problem")
    Signal    — исходящее уведомление по Incident (не "action")
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


def as_aware(dt: datetime) -> datetime:
    """SQLite не хранит tzinfo нативно (в отличие от MySQL/MariaDB): при
    чтении обратно приходит naive datetime, хотя записывался aware (UTC).
    Любое вычитание дат, где одна сторона из БД, обязано пройти через эту
    нормализацию — иначе на SQLite-варианте будет TypeError."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str | None:
    """.isoformat() с гарантией offset'а — реальный баг (2026-09-21,
    по прямому запросу пользователя, "время последнего прогона не
    правильно"): naive datetime из SQLite (см. as_aware выше) даёт
    isoformat() без 'Z'/offset ("2026-09-21T07:15:25"), а JS `new
    Date(iso)` на клиенте (timeAgo в common.js) интерпретирует такую
    строку как ЛОКАЛЬНОЕ время браузера, не UTC — на Алматы (UTC+5) это
    систематически съедало 5 часов, только что запущенный прогон
    показывался как "5ч назад". Использовать везде, где datetime из БД
    уходит наружу через API (не голый .isoformat())."""
    return as_aware(dt).isoformat() if dt is not None else None


class ProbeKind(str, enum.Enum):
    icmp_ping = "icmp_ping"
    tcp_port = "tcp_port"
    ssh_command = "ssh_command"
    snmp_get = "snmp_get"
    snmp_walk = "snmp_walk"          # обход поддерева OID со сверткой в одно число
    snmp_counter_rate = "snmp_counter_rate"  # счётчик → скорость (см. rate_engine.py)


class Vendor(str, enum.Enum):
    """Опционально на Node — известно только для сетевого оборудования,
    пусто для серверов/сервисов общего вида. Значения нужны только там, где
    от вендора реально зависит поведение (сейчас — нигде в самом движке
    опроса, задел под будущие вендор-специфичные Probe, как SSH-команды
    показа состояния порта у Cisco/Juniper в NetOpsHub)."""

    cisco_ios = "cisco_ios"
    cisco_ios_telnet = "cisco_ios_telnet"
    junos = "junos"
    generic = "generic"


class Group(Base):
    """Организационная группировка узлов — обобщённая версия NetworkGroup
    из NetOpsHub (там жёстко «министерство × контур»; здесь — произвольное
    имя, GridForge не привязан к конкретной предметной области заказчика).
    Плоская, без вложенности — если понадобится иерархия, добавлять
    parent_id отдельным шагом, не проектировать заранее вслепую."""

    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    nodes: Mapped[list["Node"]] = relationship(back_populates="group")


class Credential(Base):
    """Централизованная учётка для подключения к узлам — своя версия
    Ansible Vault group_vars из NetOpsHub (там пароль/ключ задан один раз
    на группу узлов, не вводится вручную при каждом запуске), но проще:
    без Vault, пароль лежит в этой же БД зашифрованным (Fernet, см.
    secrets_crypto.py — тот же механизм, что уже защищает
    Probe.params.password/Action.config.password).

    По прямому запросу пользователя (2026-09-21): раньше учётку спрашивал
    prompt() перед КАЖДЫМ действием на узле (бэкап/консоль/Рубка/
    Сценарии/порты) — неудобно на парке в десятки коммутаторов с общей
    учёткой. group_id=None и node_id=None и vendor=None — учётка по
    умолчанию, group_id=<N> — своя для группы, node_id=<M> — своя для
    конкретного узла (2026-09-21, тот же день: "у меня зоопарк" — парк
    смешанного оборудования). vendor=<V> — своя для вендора (2026-09-21,
    тот же день: группы здесь смешанные — в "Группа-А"/"Группа-Б · Интернет" есть и
    cisco_ios, и junos одновременно, так что логин реально зависит от
    вендора устройства, а не от того, в какую сетевую группу оно попало
    — "метка cisco или juniper... применяется на том оборудовании, где
    указана"). Порядок поиска в credentials_engine.resolve_credential:
    node -> group -> vendor -> по умолчанию. Явно переданная учётка в
    самом запросе (username в теле, как раньше) всё ещё имеет приоритет
    — центральная учётка это откат для запросов БЕЗ явной учётки, не
    единственный путь."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True)
    vendor: Mapped[Vendor | None] = mapped_column(Enum(Vendor), nullable=True)
    label: Mapped[str] = mapped_column(String(128), default="")
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    # Ровно одно из password/key_path обычно задано — как и везде в
    # GridForge, где нужен SSH/Telnet-логин (Probe kind=ssh_command,
    # Action, консоль).
    password: Mapped[str | None] = mapped_column(String(500), nullable=True)  # зашифровано, см. encrypt_secret
    key_path: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group | None"] = relationship()
    node: Mapped["Node | None"] = relationship()


class Integration(Base):
    """Доступ к внешней системе (Graylog/Zabbix и т.п.) — своя версия
    страницы "Интеграции" из NetOpsHub (2026-09-21, по прямому запросу
    пользователя: "надо добавить интеграцию в учётки что бы я мог
    добавлять graylog and zabbix"), тот же принцип: URL + токен, токен
    зашифрован (Fernet, secrets_crypto.py — тот же механизм, что уже
    защищает Credential.password), одна запись на ключ интеграции. Список
    допустимых ключей — INTEGRATION_REGISTRY в integrations_engine.py,
    не в БД: набор внешних систем, которые GridForge умеет опрашивать,
    меняется только кодом, не через API."""

    __tablename__ = "integrations"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    api_token: Mapped[str] = mapped_column(String(1000), nullable=False)  # зашифровано, см. encrypt_secret
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class LdapConnection(Base):
    """Домен для AD-аудита — своя версия LdapCredentialSet из NetOpsHub
    (2026-09-21, по прямому запросу пользователя: "так же добавил ldap
    подключение", в связке с переносом AD-аудита на GridForge). Там
    пароль лежит в отдельном Ansible-Vault-файле на диск, здесь — тот же
    Fernet-механизм, что уже защищает Credential.password/
    Integration.api_token (secrets_crypto.py), прямо в этой же строке.

    Bind-логин собирается в момент подключения как f"{username}@{domain}"
    (UPN), не DN — тот же приём, что в NetOpsHub, работает без знания
    точного расположения объекта учётки в дереве каталога."""

    __tablename__ = "ldap_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    dc_address: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(default=636)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    base_dn: Mapped[str] = mapped_column(String(500), nullable=False)
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    password: Mapped[str] = mapped_column(String(500), nullable=False)  # зашифровано, см. encrypt_secret
    use_ssl: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    address: Mapped[str] = mapped_column(String(255), nullable=False)
    tags: Mapped[str | None] = mapped_column(String(255), nullable=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    vendor: Mapped[Vendor | None] = mapped_column(Enum(Vendor), nullable=True)
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group | None"] = relationship(back_populates="nodes")
    probes: Mapped[list["Probe"]] = relationship(back_populates="node", cascade="all, delete-orphan")


class Probe(Base):
    """Одна проверка на узле. `interval_seconds` двигает Probe по
    собственному расписанию планировщика (см. scheduler.py) — независимо от
    остальных проверок этого же узла, в отличие от опроса "всем узлом
    разом"."""

    __tablename__ = "probes"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    kind: Mapped[ProbeKind] = mapped_column(Enum(ProbeKind), nullable=False)
    # Параметры проверки, форма зависит от kind (например {"port": 22} для
    # tcp_port) — сознательно JSON, а не позиционный строковый ключ вида
    # item key ("vfs.fs.size[/,used]") из Zabbix.
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=60)
    timeout_seconds: Mapped[float] = mapped_column(Float, default=2.0)
    enabled: Mapped[bool] = mapped_column(default=True)

    node: Mapped["Node"] = relationship(back_populates="probes")
    samples: Mapped[list["Sample"]] = relationship(back_populates="probe", cascade="all, delete-orphan")
    watches: Mapped[list["Watch"]] = relationship(back_populates="probe", cascade="all, delete-orphan")


class Sample(Base):
    """Один результат проверки. `ok` — проверка вообще выполнилась (узел
    ответил), `value` — измеренная величина (RTT в мс, 1/0 для доступности
    порта и т.д.), интерпретация зависит от Probe.kind."""

    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=False)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    ok: Mapped[bool] = mapped_column(nullable=False)
    value: Mapped[float | None] = mapped_column(Float, nullable=True)
    detail: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Только для snmp_counter_rate: сырое показание счётчика, по которому
    # вычислена скорость в value. Нужно именно хранить, а не пересчитывать:
    # следующий опрос считает дельту относительно этого числа, а value к
    # тому моменту — уже скорость, из неё счётчик не восстановить.
    raw_value: Mapped[float | None] = mapped_column(Float, nullable=True)

    probe: Mapped["Probe"] = relationship(back_populates="samples")


class WatchOperator(str, enum.Enum):
    gt = "gt"
    lt = "lt"
    eq = "eq"
    probe_failed = "probe_failed"  # ok == False на последних N выборках


class WatchSeverity(str, enum.Enum):
    critical = "critical"
    warning = "warning"
    info = "info"


class Watch(Base):
    """Условие над последними Sample выбранного Probe. `streak_required` —
    сколько подряд выборок должны выполнять условие до открытия Incident
    (гасит одиночные всплески/дребезг), симметрично требуется для закрытия."""

    __tablename__ = "watches"

    id: Mapped[int] = mapped_column(primary_key=True)
    probe_id: Mapped[int] = mapped_column(ForeignKey("probes.id"), nullable=False)
    operator: Mapped[WatchOperator] = mapped_column(Enum(WatchOperator), nullable=False)
    threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    streak_required: Mapped[int] = mapped_column(Integer, default=1)
    severity: Mapped[WatchSeverity] = mapped_column(Enum(WatchSeverity), default=WatchSeverity.warning)
    label: Mapped[str] = mapped_column(String(255), nullable=False)

    probe: Mapped["Probe"] = relationship(back_populates="watches")


class Template(Base):
    """Набор Probe+Watch, применяемый к Node одним действием — своя версия
    шаблонов мониторинга Zabbix. КРИТИЧНО ПО ЛИЦЕНЗИИ (см. GridForge
    Rewrite Ledger, раздел «Шаблоны мониторинга»): сюда нельзя копировать
    содержимое официальных/community-шаблонов Zabbix (OID-списки, тексты
    триггеров) — только свои наборы поверх уже написанных с нуля Probe/Watch.
    Сами OID для конкретных вендоров — бери из открытых MIB/документации
    производителя, не из чужого шаблона.

    `probe_defs` — JSON-список черновиков (не FK на живые Probe — шаблон
    описывает КАК завести проверки, а не ссылается на чужие):
    [{"kind": "tcp_port", "params": {"port": 22}, "interval_seconds": 30,
      "timeout_seconds": 2,
      "watches": [{"operator": "probe_failed", "streak_required": 3,
                    "severity": "critical", "label": "SSH недоступен"}]}]
    """

    __tablename__ = "templates"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    vendor: Mapped[Vendor | None] = mapped_column(Enum(Vendor), nullable=True)
    probe_defs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ApiKeyRole(str, enum.Enum):
    """Роли по возрастанию прав (см. auth.py: ROLE_RANK). Разделение — по
    ФУНКЦИЯМ, не по отдельным эндпоинтам: operator делает то, что делает
    дежурный инженер (снять бэкап, прогнать аудит, запустить скан), но не
    может менять сам инвентарь/правила/каналы и уж тем более выдавать
    ключи доступа. Это заметно уже, чем «admin на всё сразу», и при этом
    не требует прав на каждую операцию отдельно — такой уровень вводить
    только если реально понадобится, не авансом."""

    viewer = "viewer"      # только чтение (GET)
    operator = "operator"  # чтение + запуск операций на узлах (бэкап, аудит, скан, захват)
    admin = "admin"        # полный доступ, включая инвентарь, каналы и ключи


class ApiKey(Base):
    """Ключ доступа к API (см. auth.py) — нет пользователей/паролей/сессий,
    только ключ в заголовке `X-API-Key` + роль. Хранится хеш (SHA-256), не
    сам ключ — ключ высокоэнтропийный (32 случайных байта, не пароль
    человека), поэтому обычный быстрый хеш достаточен, bcrypt/argon2 здесь
    избыточны (та цена нужна против подбора коротких человеческих паролей,
    не против 256-битного токена)."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), default="default")
    role: Mapped[ApiKeyRole] = mapped_column(Enum(ApiKeyRole), default=ApiKeyRole.admin)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    revoked: Mapped[bool] = mapped_column(default=False)
    # Вторая ось прав (первая — role): ограничение области видимости одной
    # группой узлов. None = все группы (так ведут себя все ключи, выданные
    # до появления этого поля). Ключ с группой не видит ни узлы других
    # групп, ни узлы вообще без группы — строгая, предсказуемая граница.
    # Проверки — в auth.py (key_sees_group/require_node_access), не
    # россыпью по эндпоинтам.
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)


class User(Base):
    """Человек, входящий в веб-интерфейс по логину и паролю.

    Отдельно от ApiKey намеренно: ключ — это учётка для программы
    (скрипт, интеграция), её не «забывают» и не вводят руками. Роль и
    ограничение по группе устроены так же, как у ключа (см. ApiKeyRole),
    чтобы права не разъезжались между двумя способами входа.

    Пароль хранится только как scrypt-хеш (см. passwords.py) — в отличие
    от API-ключей, где достаточно быстрого SHA-256."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # У доменных пользователей (source="ad") здесь пустая строка: их пароль
    # живёт в AD и проверяется bind'ом, локального хеша нет — утечка нашей
    # базы не должна давать доменных учёток.
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="local")  # "local" | "ad"
    role: Mapped[ApiKeyRole] = mapped_column(Enum(ApiKeyRole), default=ApiKeyRole.viewer)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Session(Base):
    """Вход, живущий в куке. Хранится хеш токена, не сам токен — кука у
    пользователя равносильна паролю, и утёкшая копия БД не должна давать
    возможность войти чужими сессиями.

    Сессии в таблице, а не в подписанной куке, ради отзыва: выход,
    смена пароля или блокировка пользователя должны немедленно закрывать
    уже открытые сессии, а подписанную куку отозвать нечем."""

    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    user: Mapped["User"] = relationship()


class PortSnapshot(Base):
    """Снимок состояния портов узла на момент опроса.

    Снимок, а не «текущее состояние»: данные живут ровно столько, сколько
    прошло с опроса, и на схеме обязательно показывается, когда их сняли.
    Иначе выключенный вчера порт выглядел бы как выключенный сейчас."""

    __tablename__ = "port_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False, index=True)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    ok: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Разобранные порты: [{name, state, description, vlan, speed, is_trunk}].
    # JSON, а не отдельная таблица на каждый порт: снимок читается и
    # пишется целиком, по одному порту его не обновляют, а 48 строк на
    # каждый опрос каждого узла — лишний рост таблицы без пользы.
    ports: Mapped[list] = mapped_column(JSON, default=list)

    node: Mapped["Node"] = relationship()


class SweepStatus(str, enum.Enum):
    running = "running"
    done = "done"


class Sweep(Base):
    """Прогон одной читающей команды сразу по набору узлов.

    Своя реализация: у NetOpsHub похожая задача решалась очередью заданий
    в файлах и внешним Ansible-раннером. Здесь узлы опрашиваются прямо из
    приложения тем же asyncssh, что уже используется для бэкапов, — без
    второго исполнителя и без промежуточных файлов на диске.

    Команда хранится уже проверенной (см. sweep_commands): в БД не
    попадает ничего, что не прошло белый список."""

    __tablename__ = "sweeps"

    id: Mapped[int] = mapped_column(primary_key=True)
    preset_key: Mapped[str | None] = mapped_column(String(64), nullable=True)  # None = произвольный запрос
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[SweepStatus] = mapped_column(Enum(SweepStatus), default=SweepStatus.running)
    # Кто запустил — метка ключа или имя пользователя (см. auth.Principal).
    # Важно для боевой сети: по журналу должно быть видно, чей это был прогон.
    started_by: Mapped[str] = mapped_column(String(128), default="")

    results: Mapped[list["SweepResult"]] = relationship(
        back_populates="sweep", cascade="all, delete-orphan"
    )


class SweepResult(Base):
    """Результат по одному узлу. Команда своя у каждого узла: она зависит
    от вендора, поэтому хранится здесь, а не в Sweep."""

    __tablename__ = "sweep_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    sweep_id: Mapped[int] = mapped_column(ForeignKey("sweeps.id"), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    command: Mapped[str] = mapped_column(String(255), nullable=False)
    ok: Mapped[bool | None] = mapped_column(nullable=True)  # None = ещё выполняется
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    sweep: Mapped["Sweep"] = relationship(back_populates="results")
    node: Mapped["Node"] = relationship()



class Scenario(Base):
    """Именованный, заранее определённый сценарий с командами, меняющими
    конфигурацию устройства — аналог плейбука NetOpsHub (playbook_catalog.py),
    но без Ansible: та же прямая SSH/Telnet-команда, что уже используют
    Probe kind=ssh_command, Action и Sweep (см. device_client.py).

    В отличие от Sweep (произвольная читающая команда из белого списка
    глаголов show/display/ping/traceroute) здесь можно менять конфигурацию
    устройства — поэтому набор сценариев не свободный пользовательский
    ввод, а фиксированный каталог: заводит и правит его администратор
    (POST/DELETE /api/scenarios, права admin), обычные операторы только
    выбирают узлы и запускают уже готовый сценарий (POST
    /api/scenarios/{id}/run, права operator — как у Sweep/Backup).

    commands_by_vendor: {"cisco_ios": "configure terminal\n...", "junos": "configure\n..."}
    — команда за вендор может быть многострочной (одна SSH/Telnet-сессия,
    строки уходят как единый exec — тот же приём, что у Action.config.command).
    params — имена плейсхолдеров вида {ntp_server} внутри команд, только
    для формы в интерфейсе и проверки при запуске — сами значения приходят
    в каждом запуске отдельно (ScenarioRun их не хранит), не в определении
    сценария."""

    __tablename__ = "scenarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    commands_by_vendor: Mapped[dict] = mapped_column(JSON, default=dict)
    params: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    runs: Mapped[list["ScenarioRun"]] = relationship(back_populates="scenario", cascade="all, delete-orphan")


class ScenarioRun(Base):
    """Один запуск сценария на наборе узлов — журнал того, кто и когда
    менял конфигурацию массово (важно на боевой сети не меньше, чем сам
    факт изменения)."""

    __tablename__ = "scenario_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scenario_id: Mapped[int] = mapped_column(ForeignKey("scenarios.id"), nullable=False)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[SweepStatus] = mapped_column(Enum(SweepStatus), default=SweepStatus.running)
    started_by: Mapped[str] = mapped_column(String(128), default="")

    scenario: Mapped["Scenario"] = relationship(back_populates="runs")
    results: Mapped[list["ScenarioResult"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )


class ScenarioResult(Base):
    """Результат сценария по одному узлу."""

    __tablename__ = "scenario_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("scenario_runs.id"), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    ok: Mapped[bool | None] = mapped_column(nullable=True)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    run: Mapped["ScenarioRun"] = relationship(back_populates="results")
    node: Mapped["Node"] = relationship()



class ChannelKind(str, enum.Enum):
    webhook = "webhook"
    telegram = "telegram"
    apprise = "apprise"


class Channel(Base):
    """Канал доставки Signal (см. signal.py). По умолчанию глобальный —
    получает все Incident выше своего min_severity. `node_id`/`watch_id`
    сужают охват (оба опциональны, None = без сужения по этому
    признаку): `watch_id` — только инциденты этого конкретного Watch;
    `node_id` — только инциденты узла (по всем его Watch). Если задано
    и то, и другое — на практике избыточно (watch уже принадлежит
    ровно одному node), сужение по watch_id просто более узкое и
    "выигрывает" в фильтре dispatch()."""

    __tablename__ = "channels"

    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[ChannelKind] = mapped_column(Enum(ChannelKind), nullable=False)
    # webhook: {"url": "..."} ; telegram: {"bot_token": "...", "chat_id": "..."} ;
    # apprise: {"url": "<apprise-формат, напр. slack://.../..., ntfy://topic, mailto://...>"}
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(default=True)
    min_severity: Mapped[WatchSeverity] = mapped_column(Enum(WatchSeverity), default=WatchSeverity.info)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True)
    watch_id: Mapped[int | None] = mapped_column(ForeignKey("watches.id"), nullable=True)


class Backup(Base):
    """Снимок конфигурации узла — своя версия backup_cisco.yml/
    backup_juniper.yml из NetOpsHub, но БЕЗ git: там нашёлся реальный баг
    (несколько устройств бэкапятся параллельно → конкурентные git-процессы
    рвут объекты общего репозитория, пришлось чинить вручную + вводить
    flock). Здесь снимки — просто строки в SQLite, история по node_id уже
    атомарна на уровне БД, нет отдельного слоя (git), который можно
    повредить параллельной записью.

    `changed` — отличается ли content от предыдущего снимка этого узла
    (вычисляется при создании, не на чтении — чтобы не гонять diff по всей
    истории при каждом GET)."""

    __tablename__ = "backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    taken_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    changed: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)

    node: Mapped["Node"] = relationship()


class ScanStatus(str, enum.Enum):
    running = "running"
    done = "done"
    failed = "failed"


class Scan(Base):
    """Nmap-скан диапазона — своя версия network discovery из NetOpsHub
    (там — playbook + XML в data/scans/, разбор — отдельный nmap_parser.py).
    Здесь — прямой asyncio-подпроцесс nmap, разбор XML сразу в БД, без
    промежуточных файлов на диске."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.running)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)

    hosts: Mapped[list["ScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ScanHost(Base):
    __tablename__ = "scan_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    open_ports: Mapped[list] = mapped_column(JSON, default=list)  # [{"port":22,"service":"ssh"}, ...]

    scan: Mapped["Scan"] = relationship(back_populates="hosts")


class DiscoveryScanSchedule(Base):
    """Плановый (по расписанию) CIDR-скан с оповещением о новых
    устройствах (docs/landscape-report.md, п.4.1 — источник идеи:
    NetAlertX, непрерывное обнаружение с алертом на новый MAC/IP). Та же
    идея, что у VulnScanSchedule/CableDiscoverySchedule: раз в неделю, в
    заданное время. Не привязан к группе — как и сам Scan (CIDR может
    покрывать сразу несколько групп/сегментов), оповещение уходит на все
    включённые Channel без node_id/watch_id (см. signal.notify_new_devices)."""

    __tablename__ = "discovery_scan_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    ports: Mapped[str | None] = mapped_column(String(255), nullable=True)
    weekday: Mapped[int] = mapped_column(nullable=False)  # 0=понедельник .. 6=воскресенье
    start_time: Mapped[str] = mapped_column(String(5), nullable=False)  # "HH:MM"
    enabled: Mapped[bool] = mapped_column(default=True)
    last_triggered_on: Mapped[str | None] = mapped_column(String(10), nullable=True)  # "YYYY-MM-DD"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class VulnScanProfile(str, enum.Enum):
    """5 профилей — перенесено из NetOpsHub (playbook_catalog.NMAP_PROFILES),
    те же имена и подписи, чтобы отчёт для проверяющего выглядел так же,
    как раньше. vuln — единственный профиль, который реально ищет
    уязвимости (NSE-скрипты категории vuln); остальные — вспомогательные
    (обнаружение узлов/портов/ОС), их находки тоже пишутся в реестр, но
    строкой "не выявлено", если findings нет."""

    ping = "ping"
    quick = "quick"
    full_ports = "full_ports"
    vuln = "vuln"
    os = "os"


VULN_SCAN_PROFILE_LABELS: dict[str, str] = {
    "ping": "Обнаружение узлов (быстрый ping-скан)",
    "quick": "Быстрое сканирование портов (top 100)",
    "full_ports": "Полное сканирование портов (все 65535)",
    "vuln": "Проверка на известные уязвимости (NSE vuln)",
    "os": "Определение ОС",
}


class VulnScanStatus(str, enum.Enum):
    running = "running"
    done = "done"
    failed = "failed"


class VulnScan(Base):
    """Скан на известные уязвимости (и вспомогательные nmap-профили) —
    перенос функции NetOpsHub "проверка на уязвимости". В отличие от
    Scan (network discovery по CIDR), у VulnScan всегда есть группа: сюда
    же завязан накопительный гос-отчёт (см. app/vuln_register.py) — один
    .xlsx на группу, "Отчёт о проведении оценки уязвимости сетевых
    ресурсов {группа}", формат под официальный бланк (см. заголовки в
    vuln_register.py)."""

    __tablename__ = "vuln_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    profile: Mapped[VulnScanProfile] = mapped_column(Enum(VulnScanProfile), nullable=False)
    status: Mapped[VulnScanStatus] = mapped_column(Enum(VulnScanStatus), default=VulnScanStatus.running)
    responsible: Mapped[str | None] = mapped_column(String(255), nullable=True)  # Ф.И.О. и должность — для отчёта
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # Заполняется при завершении: попал ли скан в накопительный .xlsx-реестр
    # (True), или ничего не найдено И встраивать было нечего — на деле
    # ingest_scan() всегда пишет хотя бы строку "не выявлено", так что
    # False реально означает только "ещё не дошли/сбой".
    ingested: Mapped[bool] = mapped_column(default=False)

    group: Mapped["Group"] = relationship()
    hosts: Mapped[list["VulnScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class VulnScanHost(Base):
    __tablename__ = "vuln_scan_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("vuln_scans.id"), nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(16), default="up")
    # [{"port": "tcp/80", "script_id": "...", "severity": "vulnerable"|
    #   "likely"|"unknown", "cves": ["CVE-..."], "summary": "..."}, ...]
    findings: Mapped[list] = mapped_column(JSON, default=list)

    scan: Mapped["VulnScan"] = relationship(back_populates="hosts")


class VulnScanSchedule(Base):
    """Плановый (по расписанию) запуск сканов уязвимостей — раз в неделю,
    в заданный день/время, по выбранному набору профилей, без ручного
    нажатия "Запустить". Проверяется Scheduler.run_forever() (см.
    app/scheduler.py, run_due_vuln_schedules) раз в минуту: если сейчас
    нужный weekday и текущее время >= start_time, а сегодня ещё не
    запускали (last_triggered_on != today) — запускаются все профили
    из profiles последовательно (не параллельно — один и тот же набор
    хостов, гонка по одной цели ни к чему)."""

    __tablename__ = "vuln_scan_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    # список ключей VulnScanProfile, например ["ping","quick","full_ports","vuln","os"]
    profiles: Mapped[list] = mapped_column(JSON, default=list)
    weekday: Mapped[int] = mapped_column(nullable=False)  # 0=понедельник .. 6=воскресенье (datetime.weekday())
    start_time: Mapped[str] = mapped_column(String(5), nullable=False)  # "HH:MM"
    end_time: Mapped[str | None] = mapped_column(String(5), nullable=True)  # ориентировочно, не жёсткий обрыв
    responsible: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    # "YYYY-MM-DD" даты последнего запуска — простой строковый guard от повторного
    # срабатывания в тот же день (проверка идёт раз в минуту)
    last_triggered_on: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group"] = relationship()


class CableLinkStatus(str, enum.Enum):
    active = "active"
    spare = "spare"
    damaged = "damaged"


CABLE_LINK_STATUS_LABELS: dict[str, str] = {
    "active": "в работе",
    "spare": "резерв",
    "damaged": "повреждён",
}


class CableLink(Base):
    """Журнал учёта кабельных соединений — перенос функции NetOpsHub
    (бумажный/Excel-журнал "куда физически идёт кабель"). Гибридная
    схема, не обе стороны — реальные узлы GridForge: один конец всегда
    привязан к реальному Node+порту (порт валидируется по последнему
    снимку портов узла, см. /api/nodes/{id}/ports — тот же справочник,
    что уже использует страница Порты), другой конец — свободный текст
    (патч-панель/розетка/ПК/принтер редко сами являются опрашиваемым
    узлом, требовать для них Node было бы искусственно и половину
    реальных записей просто нельзя было бы завести)."""

    __tablename__ = "cable_links"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    port_name: Mapped[str] = mapped_column(String(64), nullable=False)
    other_label: Mapped[str] = mapped_column(String(255), nullable=False)  # "каб. 305, розетка 2"
    cable_type: Mapped[str | None] = mapped_column(String(64), nullable=True)  # UTP cat5e/cat6, оптика...
    length_m: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[CableLinkStatus] = mapped_column(Enum(CableLinkStatus), default=CableLinkStatus.active)
    responsible: Mapped[str | None] = mapped_column(String(255), nullable=True)
    laid_on: Mapped[str | None] = mapped_column(String(10), nullable=True)  # "YYYY-MM-DD"
    comment: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # "manual" (руками) | "cdp" (автоопрос, см. app/cable_discovery_engine.py).
    # Автоопрос обновляет на месте только свои же source="cdp" записи,
    # ручные записи никогда не трогает, даже на том же порту.
    source: Mapped[str] = mapped_column(String(16), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group"] = relationship()
    node: Mapped["Node"] = relationship()


class CableDiscoverySchedule(Base):
    """Плановый (по расписанию) автоопрос транковых соединений через CDP
    (app/cable_discovery_engine.py) — та же идея, что у VulnScanSchedule,
    но без набора профилей: тут ровно одно действие (опросить транки),
    просто когда его включать. Проверяется тем же Scheduler.run_forever()
    раз в минуту."""

    __tablename__ = "cable_discovery_schedules"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id"), nullable=False)
    weekday: Mapped[int] = mapped_column(nullable=False)  # 0=понедельник .. 6=воскресенье
    start_time: Mapped[str] = mapped_column(String(5), nullable=False)  # "HH:MM"
    enabled: Mapped[bool] = mapped_column(default=True)
    last_triggered_on: Mapped[str | None] = mapped_column(String(10), nullable=True)  # "YYYY-MM-DD"
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group"] = relationship()


class DomainScanMethod(str, enum.Enum):
    winrm = "winrm"
    smb_domain = "smb_domain"
    smb_anonymous = "smb_anonymous"


class DomainScanCredentialSet(Base):
    """Учётка для WinRM/SMB-опроса рабочих станций — перенесено из
    NetOpsHub (app/modules/domain_scan/models.py:ScanCredentialSet).
    Приоритет применения при резолюции по IP (см.
    domain_scan_engine.resolve_credential_set): group_id+range_cidr точный
    > group_id дефолт (range_cidr=None) > range_cidr глобальный
    (group_id=None) > глобальный дефолт (оба None) — та же логика, что у
    Credential (Настройки → Учётки), но отдельная сущность: там про SSH на
    сетевое железо, тут про WinRM/SMB на Windows-станции, разные протоколы
    и разные поля (нужен domain)."""

    __tablename__ = "domain_scan_credential_sets"

    id: Mapped[int] = mapped_column(primary_key=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    range_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    method: Mapped[DomainScanMethod] = mapped_column(Enum(DomainScanMethod), nullable=False)
    fallback_method: Mapped[DomainScanMethod | None] = mapped_column(Enum(DomainScanMethod), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(128), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    password: Mapped[str | None] = mapped_column(String(500), nullable=True)  # зашифровано, см. encrypt_secret
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    group: Mapped["Group | None"] = relationship()


class DomainScan(Base):
    """Прогон доменной инвентаризации: nmap ping-скан подсети + WinRM/SMB-
    опрос каждого живого хоста (см. app/domain_scan_engine.py). Своя
    таблица, не Scan/ScanHost выше — те про открытые TCP-порты сетевого
    железа, здесь — про членство Windows-станции в домене."""

    __tablename__ = "domain_scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id"), nullable=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.running)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    live_addresses: Mapped[int | None] = mapped_column(Integer, nullable=True)

    hosts: Mapped[list["DomainScanHost"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    group: Mapped["Group | None"] = relationship()


class DomainScanHost(Base):
    __tablename__ = "domain_scan_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("domain_scans.id"), nullable=False)
    address: Mapped[str] = mapped_column(String(64), nullable=False)
    computer_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    os_caption: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # in_domain | not_in_domain | error
    error_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    method_used: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Определение типа устройства (2026-09-22, по прямому запросу
    # пользователя — "как определять принтеры/виртуалки") — manufacturer/
    # model приходят от самой Windows через ту же WinRM-сессию (честно
    # говорит "VMware Virtual Platform"/"VirtualBox" для ВМ, реальную
    # модель для физического железа), http_banner — отдельный лёгкий
    # HTTP-запрос на 80/443 для хостов без WinRM/SMB вообще (принтеры,
    # камеры, веб-морды свитчей). MAC/OUI-вендор НЕ добавлен — GridForge
    # в Docker-контейнере с NAT-сетью не видит L2/ARP ни для одной
    # подсети (проверено вживую), MAC был бы всегда пустым.
    manufacturer: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    http_banner: Mapped[str | None] = mapped_column(String(500), nullable=True)

    scan: Mapped["DomainScan"] = relationship(back_populates="hosts")


class CaptureStatus(str, enum.Enum):
    running = "running"
    done = "done"
    failed = "failed"


class Capture(Base):
    """Захват трафика по кнопке — своя версия из NetOpsHub (там тоже
    честно: контейнер/машина видит только СВОЙ сетевой интерфейс, не
    mirror-порт реального коммутатора — топология физического SPAN/RSPAN
    это отдельная задача, не про софт). Файл .pcap хранится на диске
    (`data/captures/`), в БД — только метаданные + путь, не бинарник
    целиком (в отличие от Backup, где текстовый конфиг ещё разумно класть
    прямо в SQLite — .pcap может быть десятки МБ)."""

    __tablename__ = "captures"

    id: Mapped[int] = mapped_column(primary_key=True)
    interface: Mapped[str] = mapped_column(String(64), nullable=False)
    bpf_filter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    duration_seconds: Mapped[int] = mapped_column(Integer, default=30)
    status: Mapped[CaptureStatus] = mapped_column(Enum(CaptureStatus), default=CaptureStatus.running)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    file_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)


class SyslogMessage(Base):
    """Принятые syslog-сообщения (UDP, RFC3164/RFC5424-совместимо,
    парсинг терпимый — не все устройства шлют строго по стандарту, тот же
    практический подход, что у hub-syslog в NetOpsHub). node_id заполняется,
    только если source_ip совпадает с адресом уже заведённого Node —
    иначе сообщение всё равно сохраняется (source_ip как есть), просто без
    привязки."""

    __tablename__ = "syslog_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int | None] = mapped_column(ForeignKey("nodes.id"), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    facility: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity: Mapped[int | None] = mapped_column(Integer, nullable=True)  # 0..7, RFC5424 — не путать с WatchSeverity
    message: Mapped[str] = mapped_column(Text, nullable=False)


class FlowRecord(Base):
    """Один поток из принятого NetFlow v9 (docs/landscape-report.md,
    п.4.5) — см. app/netflow_server.py. Узкий приёмник, не полный
    ntopng: только IPv4-поля, которые реально нужны для «топ говорящих»
    (src/dst, порты, протокол, байты/пакеты), остальные поля шаблона
    молча пропускаются. `exporter_ip` — кто прислал экспорт (сам
    коммутатор/маршрутизатор), не путать с src_addr/dst_addr самого
    потока трафика."""

    __tablename__ = "flow_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    exporter_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_addr: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_addr: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[int | None] = mapped_column(Integer, nullable=True)  # номер протокола IANA (6=TCP, 17=UDP...)
    byte_count: Mapped[int] = mapped_column(Integer, default=0)
    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)


class AdAuditRun(Base):
    """Один прогон AD-аудита (PingCastle-style, но свои проверки с нуля —
    см. app/ad_audit_engine.py: привилегированные аккаунты, аномалии
    userAccountControl, потенциальный Kerberoasting). Учётка для LDAP-
    подключения передаётся только в запросе на запуск, в БД НЕ хранится
    (тот же принцип, что и SSH/SNMP-параметры Probe — секреты не оседают в
    истории без необходимости)."""

    __tablename__ = "ad_audit_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    server: Mapped[str] = mapped_column(String(255), nullable=False)
    search_base: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ok: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)

    findings: Mapped[list["AdFinding"]] = relationship(back_populates="run", cascade="all, delete-orphan")


class AdFinding(Base):
    __tablename__ = "ad_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("ad_audit_runs.id"), nullable=False)
    check_name: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[WatchSeverity] = mapped_column(Enum(WatchSeverity), nullable=False)
    dn: Mapped[str] = mapped_column(String(500), nullable=False)
    detail: Mapped[str] = mapped_column(String(500), nullable=False)

    run: Mapped["AdAuditRun"] = relationship(back_populates="findings")


class AuditCheckKind(str, enum.Enum):
    must_contain = "must_contain"          # находка, если pattern НЕ найден
    must_not_contain = "must_not_contain"  # находка, если pattern НАЙДЕН


class AuditRule(Base):
    """Чеклист-правило по тексту конфига — своя версия config_analysis.py
    из NetOpsHub (там фиксированный чеклист: telnet_only/banner/ntp/
    stp_guard), но правила заводятся через API, не хардкодом в коде.
    Работает на тексте последнего УСПЕШНОГО Backup узла — если бэкапа ещё
    нет, единственная находка "нет бэкапа" (см. audit_engine.py), остальное
    не гадаем, тот же принцип, что и в NetOpsHub."""

    __tablename__ = "audit_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    vendor: Mapped[Vendor | None] = mapped_column(Enum(Vendor), nullable=True)  # None => применяется ко всем
    kind: Mapped[AuditCheckKind] = mapped_column(Enum(AuditCheckKind), nullable=False)
    pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[WatchSeverity] = mapped_column(Enum(WatchSeverity), default=WatchSeverity.warning)
    description: Mapped[str] = mapped_column(String(500), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)


class AuditFinding(Base):
    """Последний известный результат одного правила на одном узле —
    строка ПЕРЕЗАПИСЫВАЕТСЯ при повторном запуске аудита (не журнал
    каждого прогона), тот же принцип, что IntentCheckResult в NetOpsHub."""

    __tablename__ = "audit_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(ForeignKey("nodes.id"), nullable=False)
    rule_id: Mapped[int | None] = mapped_column(ForeignKey("audit_rules.id"), nullable=True)  # None => "нет бэкапа"
    ok: Mapped[bool] = mapped_column(nullable=False)
    detail: Mapped[str] = mapped_column(String(500), nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class ActionKind(str, enum.Enum):
    ssh_command = "ssh_command"


class Action(Base):
    """Действие по срабатыванию Watch — своя версия Zabbix action/operation
    (там реагирует на триггер, здесь на Watch), но с реальным выполнением,
    не только уведомлением (см. Channel/Signal для уведомлений — Action
    отдельно, действие может быть без единого уведомления и наоборот).
    Аналог "запусти Ansible-плейбук по алерту" из NetOpsHub — но выполняет
    произвольную SSH-команду на узле самого Probe, не завязано на Ansible.

    config для ssh_command: {"username":..., "key_path"|"password":...,
    "command":..., "port": 22 (опц.)} — тот же формат параметров, что у
    Probe kind=ssh_command (см. probes.py), намеренно: одна ментальная
    модель на оба места, где GridForge исполняет SSH."""

    __tablename__ = "actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    watch_id: Mapped[int] = mapped_column(ForeignKey("watches.id"), nullable=False)
    kind: Mapped[ActionKind] = mapped_column(Enum(ActionKind), default=ActionKind.ssh_command)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    watch: Mapped["Watch"] = relationship()


class ActionRun(Base):
    """Журнал одного выполнения Action — что реально произошло, когда
    Incident открылся (не факт совпадения условия — это Incident, а факт
    попытки действия и её результат)."""

    __tablename__ = "action_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    action_id: Mapped[int] = mapped_column(ForeignKey("actions.id"), nullable=False)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ok: Mapped[bool] = mapped_column(nullable=False)
    output: Mapped[str | None] = mapped_column(Text, nullable=True)


class Incident(Base):
    """Открытое/закрытое совпадение Watch. Дедуп: пока для (watch_id)
    существует запись с resolved_at is None — новый Incident не создаётся,
    только обновляется last_seen_at (та же идея, что дедуп алертов в
    NetOpsHub, но независимая реализация под свою схему)."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    watch_id: Mapped[int] = mapped_column(ForeignKey("watches.id"), nullable=False)
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    # Максимальный delay_minutes уже отправленного EscalationStep для этого
    # Incident (0 = ни одного шага эскалации ещё не было, только исходная
    # рассылка при открытии). Шаги применяются по возрастанию delay_minutes,
    # поэтому одного числа достаточно — не нужна отдельная таблица "что уже
    # отправлено", см. escalation_engine.py.
    last_escalated_minutes: Mapped[int] = mapped_column(Integer, default=0)

    watch: Mapped["Watch"] = relationship()


class EscalationStep(Base):
    """Один шаг многоступенчатой эскалации: если Incident остаётся
    открытым дольше `delay_minutes`, уходит повторное уведомление через
    указанный `channel` — независимо от того, подтвердили инцидент или
    нет (подтверждения/acknowledge в GridForge пока не реализованы, см.
    HANDOFF.md). `channel` сохраняет свои собственные сужения по
    severity/node/watch (см. Channel) — шаг эскалации их не обходит,
    только добавляет отправку с задержкой поверх обычной рассылки при
    открытии."""

    __tablename__ = "escalation_steps"

    id: Mapped[int] = mapped_column(primary_key=True)
    delay_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    channel_id: Mapped[int] = mapped_column(ForeignKey("channels.id"), nullable=False)
    enabled: Mapped[bool] = mapped_column(default=True)

    channel: Mapped["Channel"] = relationship()
