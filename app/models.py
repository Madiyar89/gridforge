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


class ChannelKind(str, enum.Enum):
    webhook = "webhook"
    telegram = "telegram"


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
    # webhook: {"url": "..."} ; telegram: {"bot_token": "...", "chat_id": "..."}
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
