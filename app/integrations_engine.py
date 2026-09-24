"""Доступ к внешним системам (Graylog/Zabbix) — своя версия страницы
"Интеграции" из NetOpsHub, тот же принцип хранения (URL + токен, токен
зашифрован), но на стороне GridForge, чтобы у него был собственный
источник данных для будущих фич (список проблем Zabbix, поиск по логам
Graylog), не завязанный на NetOpsHub.

INTEGRATION_REGISTRY — фиксированный список допустимых ключей и то, как
проверить, что URL/токен реально рабочие (test_connection). Список
внешних систем, которые GridForge умеет опрашивать, меняется кодом
(новая запись в этом словаре), не через API — тот же принцип, что у
Scenario.commands_by_vendor (структура фиксированная, значения — через
сайт)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable

import httpx

from app.geoip_engine import GeoipDownloadError, download_databases
from app.models import Integration
from app.secrets_crypto import decrypt_secret, encrypt_secret


class IntegrationTestError(Exception):
    pass


async def _test_zabbix(url: str, api_token: str) -> None:
    """JSON-RPC поверх HTTP, авторизация Bearer-токеном (Zabbix: Users →
    API tokens) — тот же вызов, что использует NetOpsHub для проверки."""
    headers = {"Content-Type": "application/json-rpc", "Authorization": f"Bearer {api_token}"}
    payload = {"jsonrpc": "2.0", "method": "host.get", "params": {"output": ["hostid"], "limit": 1}, "id": 1}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(url, json=payload, headers=headers)
        res.raise_for_status()
        body = res.json()
    except httpx.HTTPError as exc:
        raise IntegrationTestError(f"не удалось связаться с Zabbix API: {exc}") from exc
    except ValueError as exc:
        raise IntegrationTestError(
            "Zabbix ответил не JSON-ом — проверь, что URL указывает на api_jsonrpc.php, а не на веб-страницу"
        ) from exc
    if "error" in body:
        err = body["error"]
        raise IntegrationTestError(err.get("data") or err.get("message") or "ошибка Zabbix API")


async def _test_graylog(url: str, api_token: str) -> None:
    """Graylog REST API — токен как логин в Basic Auth с паролем "token"
    (штатный способ Graylog для API-токенов, не сессионный логин/пароль
    человека). verify=False — реальный сертификат этого Graylog
    самоподписанный (подтверждено вживую, curl требовал -k), тот же
    случай, что уже решался для внешних систем в этой инфраструктуре
    (corporate-ca.crt у исходящего HTTPS в Docker-сборках)."""
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            res = await client.get(
                url.rstrip("/") + "/api/system",
                auth=(api_token, "token"),
                headers={"Accept": "application/json", "X-Requested-By": "gridforge"},
            )
        res.raise_for_status()
    except httpx.HTTPError as exc:
        raise IntegrationTestError(f"не удалось связаться с Graylog API: {exc}") from exc


async def _test_maxmind(account_id: str, license_key: str) -> None:
    """Здесь "URL" поля интеграции переиспользован под Account ID (у
    MaxMind нет своего URL — адрес скачивания фиксирован в
    geoip_engine.py) — проверка это и есть реальное первое скачивание
    баз GeoLite2 (docs/landscape-report.md, п.4.4), не отдельный
    холостой запрос: раз учётка рабочая, справочник сразу готов к
    использованию, а не будет ждать первого планового обновления."""
    try:
        await download_databases(account_id, license_key)
    except GeoipDownloadError as exc:
        raise IntegrationTestError(str(exc)) from exc


@dataclass(frozen=True)
class IntegrationSpec:
    label: str
    url_placeholder: str
    test: Callable[[str, str], Awaitable[None]]


INTEGRATION_REGISTRY: dict[str, IntegrationSpec] = {
    "graylog": IntegrationSpec("Graylog", "http://192.0.2.115:9000", _test_graylog),
    "zabbix": IntegrationSpec("Zabbix", "http://192.0.2.243:8080/api_jsonrpc.php", _test_zabbix),
    "maxmind": IntegrationSpec("MaxMind GeoLite2 (GeoIP/ASN)", "Account ID, например 1416588", _test_maxmind),
}


def encrypt_token(token: str) -> str:
    return encrypt_secret(token)


def decrypt_token(token: str) -> str:
    return decrypt_secret(token)


def mask_integration(integration: Integration) -> dict:
    return {
        "key": integration.key,
        "url": integration.url,
        "configured": True,
    }
