"""Signal — исходящее уведомление по вновь открытому Incident.

Реестр по ChannelKind, тот же паттерн, что и probes.py — новый канал
добавляется регистрацией функции, без правки dispatch(). Оба текущих
отправителя (webhook, telegram) — на одном общем httpx.AsyncClient (см.
main.py:lifespan), не создают соединение заново на каждое сообщение."""

from __future__ import annotations

import logging
from typing import Awaitable, Callable

import httpx
from sqlalchemy.orm import Session

from app.models import Channel, ChannelKind, Incident, WatchSeverity

logger = logging.getLogger("gridforge.signal")

_SEVERITY_RANK = {WatchSeverity.info: 0, WatchSeverity.warning: 1, WatchSeverity.critical: 2}

ChannelSender = Callable[[httpx.AsyncClient, Channel, Incident, str], Awaitable[None]]

_REGISTRY: dict[ChannelKind, ChannelSender] = {}


def register(kind: ChannelKind) -> Callable[[ChannelSender], ChannelSender]:
    def decorator(fn: ChannelSender) -> ChannelSender:
        _REGISTRY[kind] = fn
        return fn

    return decorator


def _format_message(incident: Incident) -> str:
    watch = incident.watch
    node_name = watch.probe.node.name
    severity_label = {"critical": "КРИТИЧНО", "warning": "предупреждение", "info": "инфо"}[watch.severity.value]
    return f"[{severity_label}] {node_name}: {incident.detail}"


@register(ChannelKind.webhook)
async def _send_webhook(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    url = channel.config.get("url")
    if not url:
        logger.warning("channel_id=%s (webhook): config.url не задан", channel.id)
        return
    await client.post(
        url,
        json={
            "incident_id": incident.id,
            "severity": incident.watch.severity.value,
            "message": message,
            "opened_at": incident.opened_at.isoformat(),
        },
        timeout=5.0,
    )


@register(ChannelKind.telegram)
async def _send_telegram(client: httpx.AsyncClient, channel: Channel, incident: Incident, message: str) -> None:
    bot_token = channel.config.get("bot_token")
    chat_id = channel.config.get("chat_id")
    if not bot_token or not chat_id:
        logger.warning("channel_id=%s (telegram): config.bot_token/chat_id не заданы", channel.id)
        return
    await client.post(
        f"https://api.telegram.org/bot{bot_token}/sendMessage",
        json={"chat_id": chat_id, "text": message},
        timeout=5.0,
    )


async def dispatch(client: httpx.AsyncClient, db: Session, incidents: list[Incident]) -> None:
    if not incidents:
        return
    channels = db.query(Channel).filter(Channel.enabled.is_(True)).all()
    if not channels:
        return
    for incident in incidents:
        message = _format_message(incident)
        rank = _SEVERITY_RANK[incident.watch.severity]
        for channel in channels:
            if rank < _SEVERITY_RANK[channel.min_severity]:
                continue
            sender = _REGISTRY.get(channel.kind)
            if sender is None:
                continue
            try:
                await sender(client, channel, incident, message)
            except httpx.HTTPError as exc:
                logger.warning("channel_id=%s: доставка не удалась: %s", channel.id, exc)
