from __future__ import annotations

from pydantic import BaseModel

from app.models import (
    ActionKind,
    ApiKeyRole,
    AuditCheckKind,
    ChannelKind,
    ProbeKind,
    Vendor,
    WatchOperator,
    WatchSeverity,
)


class GroupIn(BaseModel):
    name: str


class CredentialIn(BaseModel):
    """Ровно одно из node_id/group_id/vendor (или ни одного — учётка по
    умолчанию). Приоритет при разрешении: node_id > group_id > vendor >
    умолчание. См. Credential в models.py и
    credentials_engine.resolve_credential. Пароль хранится зашифрованным
    (Fernet, secrets_crypto.py), наружу (GET /api/credentials) никогда не
    возвращается — только has_password."""

    group_id: int | None = None
    node_id: int | None = None
    vendor: Vendor | None = None
    label: str = ""
    username: str
    password: str | None = None
    key_path: str | None = None


class IntegrationIn(BaseModel):
    """URL + токен внешней системы (Graylog/Zabbix). Токен хранится
    зашифрованным, наружу (GET /api/integrations) никогда не
    возвращается — см. Integration в models.py."""

    url: str
    api_token: str


class LdapConnectionIn(BaseModel):
    """Домен для AD-аудита. Пароль хранится зашифрованным, наружу
    (GET /api/ldap-connections) никогда не возвращается — см.
    LdapConnection в models.py."""

    label: str
    dc_host: str
    port: int = 636
    domain: str
    base_dn: str
    username: str
    password: str
    use_ssl: bool = True


class NodeIn(BaseModel):
    name: str
    address: str
    tags: str | None = None
    group_id: int | None = None
    vendor: Vendor | None = None


class NodeUpdateIn(BaseModel):
    """Частичное обновление: указываются только меняемые поля. Отличать
    «поле не прислали» от «прислали null» нужно, потому что для group_id и
    vendor null — осмысленное значение (убрать из группы, забыть вендора),
    поэтому эндпоинт читает model_dump(exclude_unset=True), а не значения
    по умолчанию."""

    name: str | None = None
    address: str | None = None
    tags: str | None = None
    group_id: int | None = None
    vendor: Vendor | None = None
    active: bool | None = None


class ProbeIn(BaseModel):
    node_id: int
    kind: ProbeKind
    params: dict = {}
    interval_seconds: int = 60
    timeout_seconds: float = 2.0


class WatchIn(BaseModel):
    probe_id: int
    operator: WatchOperator
    threshold: float | None = None
    streak_required: int = 1
    severity: WatchSeverity = WatchSeverity.warning
    label: str


class ChannelIn(BaseModel):
    kind: ChannelKind
    config: dict
    min_severity: WatchSeverity = WatchSeverity.info
    node_id: int | None = None
    watch_id: int | None = None


class SweepIn(BaseModel):
    """Запуск массовой команды. Либо preset_key (кнопка), либо command
    (свой запрос) — ровно одно из двух, см. проверку в эндпоинте.

    Учётка приходит в запросе и НЕ сохраняется — тот же принцип, что у
    бэкапа и SSH-консоли."""

    node_ids: list[int]
    preset_key: str | None = None
    command: str | None = None
    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout_seconds: float = 20.0



class ScenarioIn(BaseModel):
    key: str
    label: str
    category: str | None = None
    commands_by_vendor: dict[str, str]
    params: list[str] = []


class ScenarioRunIn(BaseModel):
    node_ids: list[int]
    params: dict[str, str] = {}
    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    # Многострочные конфигурирующие команды (configure/set.../commit,
    # write memory) идут через интерактивную PTY-сессию (см.
    # ssh_client.run_ssh_config_lines) - реально дольше, чем один exec с
    # "show ..." (реальный случай: write memory на боевом железе +
    # построчные паузы вместе перевалили за старые 20с, хотя сама
    # конфигурация успешно применилась - результат ошибочно помечался
    # ok=false/timeout).
    timeout_seconds: float = 40.0



class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str
    role: ApiKeyRole = ApiKeyRole.viewer
    group_id: int | None = None


class PasswordChangeIn(BaseModel):
    password: str


class EscalationStepIn(BaseModel):
    delay_minutes: int
    channel_id: int


class ApiKeyIn(BaseModel):
    label: str
    role: ApiKeyRole = ApiKeyRole.viewer
    group_id: int | None = None  # None = ключ видит все группы


class TemplateIn(BaseModel):
    name: str
    vendor: Vendor | None = None
    probe_defs: list[dict]


class TemplateApplyIn(BaseModel):
    node_id: int


class ActionIn(BaseModel):
    watch_id: int
    kind: ActionKind = ActionKind.ssh_command
    config: dict


class BackupTriggerIn(BaseModel):
    username: str | None = None
    command: str
    key_path: str | None = None
    password: str | None = None
    port: int = 22


class PortRefreshIn(BaseModel):
    """Снятие состояния портов. Команду НЕ принимаем от клиента: она
    определяется вендором узла на сервере (см. ports_engine.STATUS_COMMANDS),
    иначе через это поле можно было бы выполнить произвольную.

    Учётка не обязательна в запросе — если не указана, берётся
    центральная (Credential, см. credentials_engine.resolve_credential)."""

    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout_seconds: float = 20.0


class PortApplyIn(BaseModel):
    """Изменение одного порта (описание/VLAN/up-down/Port Security) — хотя
    бы одно из полей обязательно, см. проверку в
    port_commands.build_port_lines. Учётка не обязательна — см.
    PortRefreshIn."""

    description: str | None = None
    vlan: str | None = None
    state: str | None = None  # "up" | "down" | None
    port_security: str | None = None  # "on" | "off" | None
    port_security_maximum: int | str | None = None
    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout_seconds: float = 40.0  # интерактивная сессия, см. комментарий у ScenarioRunIn


class PortBounceIn(BaseModel):
    """Отбить порт: shutdown -> пауза -> no shutdown."""

    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout_seconds: float = 40.0
    delay_seconds: float = 5.0


class StpProtectionApplyIn(BaseModel):
    """Root bridge + BPDU Guard (access) + Loop Guard (trunk) сразу на
    группе портов узла — см. проверки в stp_protection.build_stp_lines."""

    access_ports: list[str] = []
    trunk_ports: list[str] = []
    set_root_bridge: bool = False
    root_bridge_vlans: list[str] = []
    bpdu_guard: bool = True
    loop_guard: bool = True
    username: str | None = None
    password: str | None = None
    key_path: str | None = None
    port: int = 22
    timeout_seconds: float = 40.0


class CaptureIn(BaseModel):
    interface: str
    bpf_filter: str | None = None
    duration_seconds: int = 30


class AdAuditIn(BaseModel):
    server: str
    bind_dn: str
    bind_password: str
    search_base: str
    port: int = 636


class ScanIn(BaseModel):
    cidr: str
    ports: str | None = None


class VulnScanRunIn(BaseModel):
    profile: str  # ping | quick | full_ports | vuln | os
    responsible: str | None = None  # Ф.И.О. и должность — для отчёта


class CableLinkIn(BaseModel):
    node_id: int
    port_name: str
    other_label: str
    cable_type: str | None = None
    length_m: float | None = None
    status: str = "active"  # active | spare | damaged
    responsible: str | None = None
    laid_on: str | None = None  # "YYYY-MM-DD"
    comment: str | None = None


class CableDiscoveryScheduleIn(BaseModel):
    weekday: int  # 0=понедельник .. 6=воскресенье
    start_time: str  # "HH:MM"
    enabled: bool = True


class VulnScanScheduleIn(BaseModel):
    profiles: list[str]  # ping | quick | full_ports | vuln | os
    weekday: int  # 0=понедельник .. 6=воскресенье
    start_time: str  # "HH:MM"
    end_time: str | None = None  # ориентировочно, не жёсткий обрыв
    responsible: str | None = None
    enabled: bool = True


class DomainScanRunIn(BaseModel):
    cidr: str
    group_id: int | None = None


class DomainScanCredentialSetIn(BaseModel):
    label: str
    group_id: int | None = None
    range_cidr: str | None = None
    method: str  # winrm | smb_domain | smb_anonymous
    fallback_method: str | None = None
    domain: str | None = None
    username: str | None = None
    password: str | None = None


class ScanHostToNodeIn(BaseModel):
    name: str | None = None
    group_id: int | None = None
    vendor: Vendor | None = None


class AuditRuleIn(BaseModel):
    name: str
    vendor: Vendor | None = None
    kind: AuditCheckKind
    pattern: str
    severity: WatchSeverity = WatchSeverity.warning
    description: str
