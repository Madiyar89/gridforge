"""Signal — исходящее уведомление по вновь открытому Incident.

Реестр по ChannelKind, тот же паттерн, что и probes.py — новый канал
добавляется регистрацией функции, без правки dispatch(). Оба текущих
отправителя (webhook, telegram) — на одном общем httpx.AsyncClient (см.
main.py:lifespan), не создают соединение заново на каждое сообщение."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable
from urllib.parse import urlparse

import httpx
from sqlalchemy.orm import Session

from app.models import Channel, ChannelKind, Incident, WatchSeverity, iso
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
