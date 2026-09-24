"""GeoIP/ASN справочник для внешних адресов (docs/landscape-report.md,
п.4.4) — офлайн lookup по локальным базам MaxMind GeoLite2 (Country +
ASN), без запроса во внешний сервис на каждый IP. Учётка MaxMind хранится
как обычная Integration (key="maxmind", url=Account ID, api_token=License
key — переиспользует уже существующий Integration/encrypt_secret
механизм из integrations_engine.py, не отдельная таблица под одну пару
учётных данных).

Лицензия GeoLite2 просит не использовать данные старше периода
обновления — MaxMind обновляет базы примерно раз в неделю, поэтому
`needs_refresh()` считает базу устаревшей через REFRESH_INTERVAL_SECONDS
и вызывается из фонового расписания в scheduler.py, тот же паттерн, что
у vuln/cable/discovery-расписаний."""

from __future__ import annotations

import io
import ipaddress
import tarfile
import time
from pathlib import Path

import geoip2.database
import geoip2.errors
import httpx

from app.db import DATA_DIR

GEOIP_DIR = DATA_DIR / "geoip"
GEOIP_DIR.mkdir(parents=True, exist_ok=True)

_EDITIONS = {
    "country": "GeoLite2-Country",
    "asn": "GeoLite2-ASN",
}

REFRESH_INTERVAL_SECONDS = 7 * 24 * 3600


class GeoipDownloadError(Exception):
    pass


def _mmdb_path(edition_key: str) -> Path:
    return GEOIP_DIR / f"{_EDITIONS[edition_key]}.mmdb"


async def download_databases(account_id: str, license_key: str) -> None:
    """Реальное скачивание — используется и как проверка при сохранении
    интеграции (учётка либо рабочая, либо 401 сразу), и при плановом
    еженедельном обновлении (см. scheduler.py). MaxMind отдаёт .tar.gz с
    датированной папкой внутри — распаковываем в памяти, на диск кладём
    только сам .mmdb."""
    async with httpx.AsyncClient(timeout=30, auth=(account_id, license_key), follow_redirects=True) as client:
        for edition_key, edition_name in _EDITIONS.items():
            url = f"https://download.maxmind.com/geoip/databases/{edition_name}/download?suffix=tar.gz"
            try:
                res = await client.get(url)
            except httpx.HTTPError as exc:
                raise GeoipDownloadError(f"не удалось скачать {edition_name}: {exc}") from exc
            if res.status_code == 401:
                raise GeoipDownloadError("MaxMind отклонил Account ID/License key (401)")
            if res.status_code != 200:
                raise GeoipDownloadError(f"MaxMind вернул {res.status_code} на {edition_name}")
            try:
                with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tar:
                    member = next((m for m in tar.getmembers() if m.name.endswith(".mmdb")), None)
                    if member is None:
                        raise GeoipDownloadError(f"в архиве {edition_name} не нашлось .mmdb")
                    extracted = tar.extractfile(member)
                    _mmdb_path(edition_key).write_bytes(extracted.read())
            except tarfile.TarError as exc:
                raise GeoipDownloadError(f"не удалось распаковать {edition_name}: {exc}") from exc
    _readers_cache.clear()


_readers_cache: dict[str, geoip2.database.Reader] = {}


def _reader(edition_key: str) -> geoip2.database.Reader | None:
    path = _mmdb_path(edition_key)
    if not path.exists():
        return None
    cached = _readers_cache.get(edition_key)
    if cached is not None:
        return cached
    reader = geoip2.database.Reader(str(path))
    _readers_cache[edition_key] = reader
    return reader


def databases_present() -> bool:
    return all(_mmdb_path(k).exists() for k in _EDITIONS)


def needs_refresh() -> bool:
    if not databases_present():
        return True
    oldest = min(_mmdb_path(k).stat().st_mtime for k in _EDITIONS)
    return (time.time() - oldest) >= REFRESH_INTERVAL_SECONDS


def lookup(ip: str) -> dict | None:
    """None для приватных/loopback/multicast/зарезервированных адресов
    (это ожидаемо — свой узел без внешнего IP, не ошибка) и для адресов,
    которых нет в базе (свежий блок, ещё не попавший в GeoLite2)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return None

    result: dict = {}
    country_reader = _reader("country")
    if country_reader is not None:
        try:
            resp = country_reader.country(ip)
            if resp.country.iso_code:
                result["country"] = resp.country.iso_code
                result["country_name"] = resp.country.name
        except geoip2.errors.AddressNotFoundError:
            pass
    asn_reader = _reader("asn")
    if asn_reader is not None:
        try:
            resp = asn_reader.asn(ip)
            result["asn"] = resp.autonomous_system_number
            result["as_org"] = resp.autonomous_system_organization
        except geoip2.errors.AddressNotFoundError:
            pass
    return result or None
