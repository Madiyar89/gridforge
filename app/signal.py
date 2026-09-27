"""Signal — исходящее уведомление по вновь открытому Incident.

Реестр по ChannelKind, тот же паттерн, что и probes.py — новый канал
добавляется регистрацией функции, без правки dispatch(). Оба текущих
отправителя (webhook, telegram) — на одном общем httpx.AsyncClient (см.
main.py:lifespan), не создают соединение заново на каждое сообщение."""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable
from urllib.parse import urlparse

import apprise
import httpx
from sqlalchemy.orm import Session

from app.models import Channel, ChannelKind, Incident, Node, WatchSeverity, iso
from app.secrets_crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger("gridforge.signal")

_SEVERITY_RANK = {WatchSeverity.info: 0, WatchSeverity.warning: 1, WatchSeverity.critical: 2}

# Поля Channel.config, которые надо хранить зашифрованными. Список общий
# для шифрования (main.py при создании канала) и расшифровки (отправители
# ниже): разъехавшись, они молча сломали бы доставку — поле зашифровали, а
# расшифровать забыли.
#
# `url` здесь не паранойя: в webhook-адресах Slack/Discord/Teams сам токен
# лежит в пути, то есть URL целиком является учётными данными.
CHANNEL_SECRET_FIELDS = ("bot_token", "url")


def encrypt_channel_config(config: dict) -> dict:
    result = dict(config)
    for field in CHANNEL_SECRET_FIELDS:
        if result.get(field):
            result[field] = encrypt_secret(result[field])
    return result


def _decrypted(config: dict, field: str) -> str | None:
    value = config.get(field)
    return decrypt_secret(value) if value else None


def mask_channel_config(config: dict) -> dict:
    """Версия конфига для выдачи наружу (GET /api/channels): секреты не
    отдаются даже в зашифрованном виде. Для webhook остаётся хост — по нему
    видно, куда шлёт канал, а токен из пути не раскрывается."""
    masked = {k: v for k, v in config.items() if k not in CHANNEL_SECRET_FIELDS}
    if config.get("url"):
        host = urlparse(decrypt_secret(config["url"])).netloc
        masked["url_host"] = host or "?"
    if config.get("bot_token"):
        masked["bot_token"] = "••••"
    return masked

ChannelSender = Callable[[httpx.AsyncClient, Channel, Incident, str], Awaitable[None]]

_REGISTRY: dict[ChannelKind, ChannelSender] = {}


def register(kind: ChannelKind) -> Callable[[ChannelSender], ChannelSender]:
    def decorator(fn: ChannelSender) -> ChannelSender:
        _REGISTRY[kind] = fn
        return fn

    return decorator


def format_message(incident: Incident, *, prefix: str | None = None) -> str:
    watch = incident.watch
    node_name = watch.probe.node.name
    severity_label = {"critical": "КРИТИЧНО", "warning": "предупреждение", "info": "инфо"}[watch.severity.value]
    label = f"[{severity_label}]" if prefix is None else f"[{prefix}/{severity_label}]"
    return f"{label} {node_name}: {incident.detail}"


@register(ChannelKind.webhook)
async def _send_webhook(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    url = _decrypted(channel.config, "url")
    if not url:
        logger.warning("channel_id=%s (webhook): config.url не задан", channel.id)
        return
    await client.post(
        url,
        json={
            "incident_id": incident.id,
            "severity": incident.watch.severity.value,
            "message": message,
            "opened_at": iso(incident.opened_at),
        },
        timeout=5.0,
    )


@register(ChannelKind.telegram)
async def _send_telegram(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    bot_token = _decrypted(channel.config, "bot_token")
    chat_id = channel.config.get("chat_id")
    if not bot_token or not chat_id:
        logger.warning("channel_id=%s (telegram): config.bot_token/chat_id не заданы", channel.id)
        return
    await client.post(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json={"chat_id": chat_id, "text": message},
        timeout=5.0,
    )


def _apprise_notify_sync(url: str, message: str) -> bool:
    """apprise.Apprise().notify() блокирующий (requests, не httpx) — зовётся
    только через asyncio.to_thread, никогда напрямую из корутины."""
    client = apprise.Apprise()
    if not client.add(url):
        return False
    return client.notify(body=message)


@register(ChannelKind.apprise)
async def _send_apprise(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    url = _decrypted(channel.config, "url")
    if not url:
        logger.warning("channel_id=%s (apprise): config.url не задан", channel.id)
        return
    ok = await asyncio.to_thread(_apprise_notify_sync, url, message)
    if not ok:
        logger.warning("channel_id=%s (apprise): доставка не удалась", channel.id)


def channel_matches_incident(channel: Channel, incident: Incident) -> bool:
    """Общая проверка охвата канала — используется и обычной рассылкой
    при открытии Incident (dispatch), и эскалацией (escalation_engine),
    чтобы шаг эскалации не мог обойти сужение по severity/node/watch,
    заданное на самом канале."""
    watch = incident.watch
    if _SEVERITY_RANK[watch.severity] < _SEVERITY_RANK[channel.min_severity]:
        return False
    if channel.watch_id is not None:
        return channel.watch_id == watch.id
    if channel.node_id is not None:
        return channel.node_id == watch.probe.node.id
    return True


async def send_to_channel(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    sender = _REGISTRY.get(channel.kind)
    if sender is None:
        return
    try:
        await sender(client, channel, incident, message)
    except httpx.HTTPError as exc:
        logger.warning("channel_id=%s: доставка не удалась: %s", channel.id, exc)


async def dispatch(client: httpx.AsyncClient, db: Session, incidents: list[Incident]) -> None:
    if not incidents:
        return
    channels = db.query(Channel).filter(Channel.enabled.is_(True)).all()
    if not channels:
        return
    for incident in incidents:
        message = format_message(incident)
        for channel in channels:
            if not channel_matches_incident(channel, incident):
                continue
            await send_to_channel(client, channel, incident, message)


# Оповещение о новых устройствах, найденных сканом сети (docs/
# landscape-report.md, п.4.1) — не заводится как Incident: Incident
# привязан к Watch на Probe на уже существующем Node (см. докстрин
# наверху файла), а новое устройство по определению ещё не Node. Свои
# лёгкие отправители на тот же Channel/ChannelKind, без формирования
# Incident — переиспользуют только расшифровку конфига канала.

_NEW_DEVICE_REGISTRY: dict[ChannelKind, Callable[[httpx.AsyncClient, Channel, str], Awaitable[None]]] = {}


def _register_new_device(kind: ChannelKind):
    def decorator(fn):
        _NEW_DEVICE_REGISTRY[kind] = fn
        return fn

    return decorator


@_register_new_device(ChannelKind.webhook)
async def _send_webhook_new_devices(client: httpx.AsyncClient, channel: Channel, message: str) -> None:
    url = _decrypted(channel.config, "url")
    if not url:
        logger.warning("channel_id=%s (webhook): config.url не задан", channel.id)
        return
    await client.post(url, json={"message": message}, timeout=5.0)


@_register_new_device(ChannelKind.telegram)
async def _send_telegram_new_devices(client: httpx.AsyncClient, channel: Channel, message: str) -> None:
    bot_token = _decrypted(channel.config, "bot_token")
    chat_id = channel.config.get("chat_id")
    if not bot_token or not chat_id:
        logger.warning("channel_id=%s (telegram): config.bot_token/chat_id не заданы", channel.id)
        return
    await client.post(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json={"chat_id": chat_id, "text": message},
        timeout=5.0,
    )


@_register_new_device(ChannelKind.apprise)
async def _send_apprise_new_devices(client: httpx.AsyncClient, channel: Channel, message: str) -> None:
    url = _decrypted(channel.config, "url")
    if not url:
        logger.warning("channel_id=%s (apprise): config.url не задан", channel.id)
        return
    ok = await asyncio.to_thread(_apprise_notify_sync, url, message)
    if not ok:
        logger.warning("channel_id=%s (apprise): доставка (новые устройства) не удалась", channel.id)


def format_new_devices_message(hosts: list[dict]) -> str:
    lines = "\n".join(
        f"- {h['address']}" + (f" ({h['hostname']})" if h.get("hostname") else "") for h in hosts
    )
    return f"[СЕТЬ] Обнаружены новые устройства ({len(hosts)}):\n{lines}"


async def notify_new_devices(client: httpx.AsyncClient, db: Session, hosts: list[dict]) -> None:
    """hosts — [{"address": ..., "hostname": ...}, ...], уже отфильтрованные
    вызывающей стороной (scan_engine.py) на "нет такого Node". Оповещение
    уходит на все включённые каналы БЕЗ сужения по node_id/watch_id —
    сужение по конкретному узлу здесь бессмысленно (устройство ещё не
    узел), поэтому используются только по-настоящему общие каналы."""
    if not hosts:
        return
    channels = (
        db.query(Channel)
        .filter(Channel.enabled.is_(True), Channel.node_id.is_(None), Channel.watch_id.is_(None))
        .all()
    )
    if not channels:
        return
    message = format_new_devices_message(hosts)
    for channel in channels:
        sender = _NEW_DEVICE_REGISTRY.get(channel.kind)
        if sender is None:
            continue
        try:
            await sender(client, channel, message)
        except httpx.HTTPError as exc:
            logger.warning("channel_id=%s: доставка (новые устройства) не удалась: %s", channel.id, exc)


async def notify_flow_alert(client: httpx.AsyncClient, db: Session, channel_id: int, message: str) -> None:
    """Оповещение по порогу трафика (FlowAlertRule, docs/landscape-report.md
    §4.5) — тот же принцип, что и notify_new_devices: событие не привязано
    к Watch на Probe, рассылка мимо Incident, переиспользует только уже
    существующие отправители по ChannelKind (тот же реестр). В отличие от
    notify_new_devices — рассылка на ОДИН конкретный канал (тот, что указан
    в самом правиле), не на все общие каналы разом: порог трафика — свойство
    конкретного правила, не общесетевое событие."""
    channel = db.get(Channel, channel_id)
    if channel is None or not channel.enabled:
        return
    sender = _NEW_DEVICE_REGISTRY.get(channel.kind)
    if sender is None:
        return
    try:
        await sender(client, channel, message)
    except httpx.HTTPError as exc:
        logger.warning("channel_id=%s: доставка (порог трафика) не удалась: %s", channel.id, exc)


async def notify_flow_anomaly(client: httpx.AsyncClient, db: Session, message: str) -> None:
    """Оповещение по эвристике аномалии трафика (port-scan/SYN-скан, rogue
    DHCP, DHCP starvation, DNS-аномалия — см. flow_alerts_engine.py) — та же
    ситуация, что у notify_new_devices: находка не привязана к конкретному
    уже заведённому Node/Watch (это как раз сигнал О НЁМ, не результат его
    Probe), заводить как Incident было бы смысловой натяжкой. В отличие от
    notify_flow_alert (FlowAlertRule, один явно настроенный канал на
    правило) — эти эвристики не настраиваются per-канал, поэтому рассылка
    на все общие каналы, тот же охват, что у notify_new_devices."""
    channels = (
        db.query(Channel)
        .filter(Channel.enabled.is_(True), Channel.node_id.is_(None), Channel.watch_id.is_(None))
        .all()
    )
    if not channels:
        return
    for channel in channels:
        sender = _NEW_DEVICE_REGISTRY.get(channel.kind)
        if sender is None:
            continue
        try:
            await sender(client, channel, message)
        except httpx.HTTPError as exc:
            logger.warning("channel_id=%s: доставка (аномалия трафика) не удалась: %s", channel.id, exc)


def format_security_event_message(source_ip: str, node_name: str | None, description: str) -> str:
    who = node_name or source_ip
    return f"[БЕЗОПАСНОСТЬ] {who}: {description}"


async def notify_security_event(
    client: httpx.AsyncClient,
    db: Session,
    node_id: int | None,
    source_ip: str,
    description: str,
) -> None:
    """Оповещение о реально сработавшем защитном механизме коммутатора (DAI/
    DHCP snooping/port-security), распознанном в сыром syslog (см.
    syslog_server.py._detect_security_event) — тот же принцип обхода
    Incident, что у notify_new_devices/notify_flow_alert/notify_flow_anomaly:
    у события нет Watch на Probe (это разовое системное сообщение, не
    результат периодической выборки), заводить его как Incident было бы
    натяжкой поверх схемы (Incident.watch_id NOT NULL).

    В отличие от notify_new_devices/notify_flow_anomaly — здесь узел, как
    правило, ИЗВЕСТЕН (source_ip UDP-датаграммы совпал с уже заведённым
    Node), поэтому в дополнение к общим каналам (node_id IS NULL) уходит и
    на каналы, сужённые именно на этот Node — так же, как per-node сужение
    учитывается в channel_matches_incident() для обычных Incident."""
    node_name = None
    if node_id is not None:
        node = db.get(Node, node_id)
        node_name = node.name if node else None
    channels = (
        db.query(Channel)
        .filter(Channel.enabled.is_(True), Channel.watch_id.is_(None))
        .all()
    )
    channels = [c for c in channels if c.node_id is None or c.node_id == node_id]
    if not channels:
        return
    message = format_security_event_message(source_ip, node_name, description)
    for channel in channels:
        sender = _NEW_DEVICE_REGISTRY.get(channel.kind)
        if sender is None:
            continue
        try:
            await sender(client, channel, message)
        except httpx.HTTPError as exc:
            logger.warning("channel_id=%s: доставка (security-событие) не удалась: %s", channel.id, exc)
