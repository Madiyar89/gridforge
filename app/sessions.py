"""Сессии веб-входа: создание, проверка, отзыв.

Токен сессии живёт в httponly-куке и в БД — только как SHA-256-хеш.
Быстрый хеш здесь уместен (в отличие от паролей, см. passwords.py):
токен — 32 случайных байта, перебирать его бессмысленно, а проверять
приходится на каждый запрос.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import timedelta

from sqlalchemy.orm import Session as DbSession

from app.models import Session, User, _now, as_aware

COOKIE_NAME = "gridforge_session"
SESSION_TTL = timedelta(days=7)

# По умолчанию False — реальный деплой (deploy/gridforge.service,
# боевой 192.0.2.244) сегодня обслуживается напрямую по HTTP, без TLS-
# терминации (нет reverse-proxy перед uvicorn, в отличие от NetOpsHub с
# его Caddy); Secure=True по умолчанию сделал бы куку нерабочей прямо
# сейчас — браузер (и httpx/TestClient) молча не отправит Secure-куку
# обратно по HTTP-соединению. Включать явно (GRIDFORGE_COOKIE_SECURE=1),
# когда перед GridForge реально появится TLS (свой Caddy/nginx или
# терминация на балансировщике) — тогда отсутствие Secure станет
# реальной дырой, а не текущим фактом транспорта.
COOKIE_SECURE = os.environ.get("GRIDFORGE_COOKIE_SECURE", "") == "1"


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_session(db: DbSession, user: User) -> str:
    """Возвращает сырой токен для куки; в БД уходит только его хеш."""
    raw_token = secrets.token_urlsafe(32)
    db.add(
        Session(
            token_hash=_hash_token(raw_token),
            user_id=user.id,
            expires_at=_now() + SESSION_TTL,
        )
    )
    user.last_login_at = _now()
    db.commit()
    return raw_token


def resolve_session(db: DbSession, raw_token: str | None) -> User | None:
    """Пользователь по токену куки, если сессия жива."""
    if not raw_token:
        return None
    session = db.query(Session).filter(Session.token_hash == _hash_token(raw_token)).first()
    if session is None:
        return None
    if as_aware(session.expires_at) <= _now():
        # Протухшую чистим сразу: иначе таблица копила бы мёртвые строки,
        # а ретеншн про неё ничего не знает.
        db.delete(session)
        db.commit()
        return None
    user = session.user
    if user is None or not user.active:
        return None
    return user


def revoke_session(db: DbSession, raw_token: str | None) -> None:
    if not raw_token:
        return
    db.query(Session).filter(Session.token_hash == _hash_token(raw_token)).delete(synchronize_session=False)
    db.commit()


def bootstrap_first_user(db: DbSession) -> bool:
    """Первый запуск: заводим встроенного админа, если пользователей нет.

    Возвращает True, если учётка только что создана — вызывающая сторона
    показывает предупреждение о смене пароля. Валидация пароля здесь
    намеренно не применяется: встроенный пароль заведомо слабый, он и
    существует лишь для первого входа."""
    from app.models import ApiKeyRole
    from app.passwords import DEFAULT_ADMIN_PASSWORD, DEFAULT_ADMIN_USERNAME, hash_password

    if db.query(User).count() > 0:
        return False
    db.add(
        User(
            username=DEFAULT_ADMIN_USERNAME,
            password_hash=hash_password(DEFAULT_ADMIN_PASSWORD),
            role=ApiKeyRole.admin,
        )
    )
    db.commit()
    return True


def revoke_all_for_user(db: DbSession, user_id: int) -> int:
    """Все сессии пользователя. Нужно при смене пароля и блокировке: иначе
    уже открытые сессии продолжали бы работать, и смена пароля не
    выгоняла бы того, ради кого её делают."""
    removed = db.query(Session).filter(Session.user_id == user_id).delete(synchronize_session=False)
    db.commit()
    return removed
