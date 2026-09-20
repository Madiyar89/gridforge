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


class NodeIn(BaseModel):
    name: str
    address: str
    tags: str | None = None
    group_id: int | None = None
    vendor: Vendor | None = None


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


class EscalationStepIn(BaseModel):
    delay_minutes: int
    channel_id: int


class ApiKeyIn(BaseModel):
    label: str
    role: ApiKeyRole = ApiKeyRole.viewer


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
    username: str
    command: str
    key_path: str | None = None
    password: str | None = None
    port: int = 22


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
