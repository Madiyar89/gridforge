"""Вход через OIDC SSO (docs/landscape-report.md, §4.8) — отдельная от
LDAP схема входа (Keycloak/Azure AD/Google Workspace и т.п. — любой
провайдер со стандартным OpenID Connect Discovery), но заводит того же
User/Session, что и локальный/AD-вход (см. app/sessions.py) — роль и
область по группе хранятся у нас так же, как для AD (в провайдере их
взять неоткуда).

Проверка личности — через userinfo_endpoint с access_token, а НЕ через
самостоятельную проверку подписи id_token (JWKS/RS256): провайдер сам
валидирует Bearer-токен на своей стороне при обращении к userinfo, это
даёт тот же уровень доверия без добавления JWT-библиотеки в зависимости
— тот же принцип экономии, что уже применялся для остальных интеграций
этого проекта (не тащить библиотеку туда, где хватает HTTP-вызова).

Состояние между /auth/oidc/login и /auth/oidc/callback (state для CSRF +
code_verifier для PKCE) — НЕ новая таблица в БД, а зашифрованная
(secrets_crypto.py, тот же Fernet-механизм, что и у секретов Channel/
Credential/Integration) короткоживущая httponly-кука: расшифровать её
может только этот процесс, подделать состояние снаружи нельзя, а
поднимать ради двух короткоживущих полей отдельную таблицу — только
чтобы записи протухали быстрее, чем ретеншн успел бы их подобрать.

Настраивается переменными окружения — тот же принцип, что у AD:

  GRIDFORGE_OIDC_ISSUER         адрес issuer (например https://keycloak.example/realms/gridforge)
  GRIDFORGE_OIDC_CLIENT_ID      client_id, заведённый на стороне провайдера
  GRIDFORGE_OIDC_CLIENT_SECRET  client_secret (пусто — public-клиент, только PKCE)
  GRIDFORGE_OIDC_DEFAULT_ROLE   роль при первом входе (viewer по умолчанию)
  GRIDFORGE_OIDC_VERIFY_CERT    проверять TLS-сертификат провайдера (по умолчанию да)
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import time
from urllib.parse import urlencode

import httpx
from sqlalchemy.orm import Session

from app.models import ApiKeyRole, User, _now
from app.secrets_crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger("gridforge.oidc_auth")

STATE_COOKIE_NAME = "gridforge_oidc_state"
STATE_TTL_SECONDS = 300  # достаточно на весь визит на страницу входа провайдера, не дольше
_DISCOVERY_CACHE_TTL_SECONDS = 3600

_discovery_cache: dict[str, tuple[float, dict]] = {}


def oidc_enabled() -> bool:
    return bool(os.environ.get("GRIDFORGE_OIDC_ISSUER") and os.environ.get("GRIDFORGE_OIDC_CLIENT_ID"))


def _default_role() -> ApiKeyRole:
    raw = (os.environ.get("GRIDFORGE_OIDC_DEFAULT_ROLE") or "viewer").strip().lower()
    try:
        return ApiKeyRole(raw)
    except ValueError:
        logger.warning("GRIDFORGE_OIDC_DEFAULT_ROLE=%r не роль — беру viewer", raw)
        return ApiKeyRole.viewer


def _verify_cert() -> bool:
    return (os.environ.get("GRIDFORGE_OIDC_VERIFY_CERT") or "1").strip().lower() not in {"0", "false", "no"}


class OidcError(Exception):
    pass


async def _discovery() -> dict:
    """OpenID Connect Discovery (RFC 8414-подобный /.well-known/
    openid-configuration) — кэшируется в памяти процесса на час, чтобы не
    ходить к провайдеру на каждый /auth/oidc/login."""
    issuer = os.environ["GRIDFORGE_OIDC_ISSUER"].rstrip("/")
    cached = _discovery_cache.get(issuer)
    if cached is not None and time.monotonic() - cached[0] < _DISCOVERY_CACHE_TTL_SECONDS:
        return cached[1]
    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10, verify=_verify_cert()) as client:
        try:
            res = await client.get(url)
            res.raise_for_status()
            doc = res.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"не удалось получить OIDC discovery ({url}): {exc}") from exc
        except ValueError as exc:
            raise OidcError(f"OIDC discovery ({url}) вернул не JSON") from exc
    _discovery_cache[issuer] = (time.monotonic(), doc)
    return doc


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def make_pkce_pair() -> tuple[str, str]:
    """(code_verifier, code_challenge) — S256, RFC 7636. PKCE защищает от
    перехвата authorization code даже для конфиденциальных клиентов
    (client_secret), не только для public — включён всегда."""
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def safe_redirect_path(candidate: str | None, default: str = "/index.html") -> str:
    """`next`/`redirect_after` приходит от пользователя (query-параметр на
    /auth/oidc/login) и в конце потока используется как есть в
    RedirectResponse — без этой проверки это open redirect: ссылку вида
    /auth/oidc/login?next=https://evil.example можно разослать жертве,
    она честно пройдёт SSO на настоящем домене GridForge и в конце уйдёт
    на сторонний сайт. Разрешён только локальный путь с одним ведущим
    "/" — не "//host/..." (protocol-relative тоже уводит на другой хост)."""
    if candidate and candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return default


def pack_state_cookie(state: str, code_verifier: str, redirect_after: str) -> str:
    redirect_after = safe_redirect_path(redirect_after)
    payload = json.dumps({"state": state, "code_verifier": code_verifier, "redirect_after": redirect_after, "created_at": time.time()})
    return encrypt_secret(payload)


def unpack_state_cookie(raw_cookie: str | None) -> dict | None:
    if not raw_cookie:
        return None
    try:
        payload = json.loads(decrypt_secret(raw_cookie))
    except Exception:
        return None  # подделанная/битая кука — считаем состояние отсутствующим, не 500
    if time.time() - payload.get("created_at", 0) > STATE_TTL_SECONDS:
        return None
    return payload


async def build_authorize_url(redirect_uri: str, redirect_after: str) -> tuple[str, str]:
    """Возвращает (authorize_url для редиректа, значение state-куки)."""
    doc = await _discovery()
    authorize_endpoint = doc.get("authorization_endpoint")
    if not authorize_endpoint:
        raise OidcError("OIDC discovery не содержит authorization_endpoint")
    state = _b64url(secrets.token_bytes(16))
    verifier, challenge = make_pkce_pair()
    params = {
        "response_type": "code",
        "client_id": os.environ["GRIDFORGE_OIDC_CLIENT_ID"],
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    url = f"{authorize_endpoint}?{urlencode(params)}"
    return url, pack_state_cookie(state, verifier, redirect_after)


async def exchange_code_for_userinfo(code: str, code_verifier: str, redirect_uri: str) -> dict:
    """Код → токены (token_endpoint) → userinfo (userinfo_endpoint).
    Отдельные HTTP-вызовы, не один: так провайдер сам подтверждает
    access_token при обращении к userinfo — не нужно самим проверять
    подпись id_token."""
    doc = await _discovery()
    token_endpoint = doc.get("token_endpoint")
    userinfo_endpoint = doc.get("userinfo_endpoint")
    if not token_endpoint or not userinfo_endpoint:
        raise OidcError("OIDC discovery не содержит token_endpoint/userinfo_endpoint")

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": os.environ["GRIDFORGE_OIDC_CLIENT_ID"],
        "code_verifier": code_verifier,
    }
    client_secret = os.environ.get("GRIDFORGE_OIDC_CLIENT_SECRET")
    if client_secret:
        data["client_secret"] = client_secret

    async with httpx.AsyncClient(timeout=10, verify=_verify_cert()) as client:
        try:
            token_res = await client.post(token_endpoint, data=data, headers={"Accept": "application/json"})
            token_res.raise_for_status()
            tokens = token_res.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"обмен кода на токен не удался: {exc}") from exc
        access_token = tokens.get("access_token")
        if not access_token:
            raise OidcError("ответ token_endpoint без access_token")

        try:
            info_res = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
            info_res.raise_for_status()
            userinfo = info_res.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"запрос userinfo не удался: {exc}") from exc
    return userinfo


def _username_from_userinfo(userinfo: dict) -> str:
    """preferred_username — стандартное поле OIDC для логина; email/sub —
    запасные варианты для провайдеров, где preferred_username не заведён
    (замечено на части конфигураций Keycloak по умолчанию)."""
    return userinfo.get("preferred_username") or userinfo.get("email") or userinfo.get("sub") or ""


def sync_oidc_user(db: Session, userinfo: dict) -> User:
    username = _username_from_userinfo(userinfo)
    if not username:
        raise OidcError("userinfo провайдера не содержит ни preferred_username, ни email, ни sub")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        user = User(
            username=username,
            password_hash="",  # пароль живёт у провайдера, локального хеша нет — тот же приём, что у AD
            role=_default_role(),
            source="oidc",
        )
        db.add(user)
    user.last_login_at = _now()
    db.commit()
    db.refresh(user)
    return user
