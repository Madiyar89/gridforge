"""Проверка учётки по SMB на узлах группы — третий инструмент из
доразбора security-инструментов (docs/landscape-report.md), после
Nuclei и Feroxbuster. Сознательно самый узкий по возможностям срез:
только "этот логин/пароль работает на этих хостах — да/нет", ничего
больше (см. докстринг CredentialCheckRun в models.py — почему не
NetExec целиком, а напрямую через уже вендоренный impacket).

Пароль живёт только в оперативной памяти на время одного прогона —
приходит параметром в run_credential_check(), нигде не сохраняется, не
логируется. Логин — не секрет, пишется в CredentialCheckRun для
журнала."""

from __future__ import annotations

import asyncio

from app.models import CredentialCheckRun, CredentialCheckTarget, ScanStatus, _now

MAX_PARALLEL = 8
SMB_TIMEOUT_SECONDS = 6


def _check_smb_login_sync(address: str, username: str, password: str, domain: str | None) -> None:
    """Пробует SMB-логин и сразу закрывает соединение — нам не нужна
    сессия, только факт "приняло/не приняло". Бросает исключение при
    любой неудаче (неверные креды, RPC недоступен, таймаут) — вызывающая
    сторона превращает это в понятную строку для журнала."""
    from impacket.smbconnection import SMBConnection

    conn = SMBConnection(address, address, timeout=SMB_TIMEOUT_SECONDS)
    try:
        conn.login(username, password, domain or "")
    finally:
        conn.close()


async def _check_one(semaphore: asyncio.Semaphore, run_id: int, address: str, username: str, password: str, domain: str | None, get_session) -> None:
    async with semaphore:
        try:
            await asyncio.wait_for(
                asyncio.to_thread(_check_smb_login_sync, address, username, password, domain),
                timeout=SMB_TIMEOUT_SECONDS + 2,
            )
            ok, error = True, None
        except asyncio.TimeoutError:
            ok, error = False, "таймаут подключения"
        except Exception as exc:  # noqa: BLE001 — любая ошибка SMB (неверный пароль, RPC недоступен) — не наша, а результат проверки
            ok, error = False, str(exc)[:500]

    db = get_session()
    try:
        db.add(CredentialCheckTarget(run_id=run_id, address=address, ok=ok, error=error))
        db.commit()
    finally:
        db.close()


async def run_credential_check(run_id: int, targets: list[str], username: str, password: str, domain: str | None, get_session) -> None:
    """Фон: параллельно (с ограничением, тот же принцип, что у Sweep/
    domain_scan/hub_detection) пробует SMB-логин на каждый адрес,
    пишет CredentialCheckTarget по мере готовности (не пачкой в конце —
    виден прогресс, и если прогон прервётся, уже собранное не
    пропадёт), затем закрывает прогон."""
    semaphore = asyncio.Semaphore(MAX_PARALLEL)
    await asyncio.gather(
        *(
            _check_one(semaphore, run_id, address, username, password, domain, get_session)
            for address in targets
        ),
        return_exceptions=True,
    )

    db = get_session()
    try:
        run = db.get(CredentialCheckRun, run_id)
        if run is not None:
            run.status = ScanStatus.done
            run.finished_at = _now()
            db.commit()
    finally:
        db.close()
