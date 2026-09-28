"""Вход через OIDC SSO (docs/landscape-report.md, §4.8) — отдельная от
LDAP схема входа (Keycloak/Azure AD/Google Workspace и т.п. — любой
провайдер со стандартным OpenID Connect Discovery), но заводит того же
User/Session, что и локальный/AD-вход (см. app/sessions.py) — роль и
область по группе хранятся у нас так же, как для AD (в провайдере их
взять неоткуда).

Проверка личности — userinfo_endpoint с access_token остаётся источником
профиля (preferred_username/email), но с 2026-09-28 к нему добавлена
самостоятельная проверка id_token (JWKS/RS256, RFC 7515/7517): то, что
провайдер принял access_token на своей стороне при обращении к userinfo,
подтверждает лишь этот конкретный провайдер и endpoint — сам userinfo-
ответ НЕ подписан, поэтому ничего не мешало бы серверу-подделке (или
скомпрометированному промежуточному узлу) вернуть чужой sub/username.
id_token, наоборот, подписан провайдером (RS256) и его подпись можно
проверить по jwks_uri из discovery — это даёт независимую (не через
доверие к самому HTTP-ответу userinfo) проверку iss/aud/sub. Библиотека
JWT (pyjwt/python-jose) НЕ добавлена — RS256-проверка подписи сделана
вручную через cryptography (уже зависимость проекта, RSA verify/JWK
разбор — десяток строк, не тянет отдельный пакет).

Провайдер обязан прислать id_token в ответе token_endpoint — по OIDC Core
1.0 (§3.1.3.3) это гарантировано для Authorization Code Flow, когда
scope включает "openid" (см. build_authorize_url — включает всегда).
Существующая регистрация клиента в Keycloak/Azure AD/Google Workspace не
требует изменений: id_token и так уже прилетал в ответе, просто не
проверялся.

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
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from sqlalchemy.orm import Session

from app.models import ApiKeyRole, User, _now
from app.secrets_crypto import decrypt_secret, encrypt_secret

logger = logging.getLogger("gridforge.oidc_auth")

STATE_COOKIE_NAME = "gridforge_oidc_state"
STATE_TTL_SECONDS = 300  # достаточно на весь визит на страницу входа провайдера, не дольше
_DISCOVERY_CACHE_TTL_SECONDS = 3600
_JWKS_CACHE_TTL_SECONDS = 3600
# id_token живёт секунды/минуты — запас на рассинхронизацию часов между
# этим процессом и провайдером, а не на "нестрогую" проверку exp/iat.
_CLOCK_SKEW_SECONDS = 60

_discovery_cache: dict[str, tuple[float, dict]] = {}
_jwks_cache: dict[str, tuple[float, dict]] = {}


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


def _b64url_decode(value: str) -> bytes:
    padding_needed = (-len(value)) % 4
    return base64.urlsafe_b64decode(value + "=" * padding_needed)


async def _jwks(jwks_uri: str) -> dict:
    """JSON Web Key Set провайдера — кэшируется в памяти процесса на час
    (тот же принцип, что у _discovery): набор публичных ключей меняется
    редко (ротация), не на каждый вход."""
    cached = _jwks_cache.get(jwks_uri)
    if cached is not None and time.monotonic() - cached[0] < _JWKS_CACHE_TTL_SECONDS:
        return cached[1]
    async with httpx.AsyncClient(timeout=10, verify=_verify_cert()) as client:
        try:
            res = await client.get(jwks_uri)
            res.raise_for_status()
            doc = res.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"не удалось получить JWKS ({jwks_uri}): {exc}") from exc
        except ValueError as exc:
            raise OidcError(f"JWKS ({jwks_uri}) вернул не JSON") from exc
    _jwks_cache[jwks_uri] = (time.monotonic(), doc)
    return doc


def _rsa_public_key_from_jwk(jwk: dict) -> rsa.RSAPublicKey:
    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e=e, n=n).public_key()


async def verify_id_token(id_token: str, expected_issuer: str, expected_audience: str) -> dict:
    """Проверяет подпись id_token (RS256) по jwks_uri из discovery, а
    затем iss/aud/exp — независимо от того, что вернул userinfo_endpoint
    (см. модуль docstring). Возвращает claims из payload при успехе,
    иначе OidcError — вызывающий код превращает это в 401/502, не в 500."""
    parts = id_token.split(".")
    if len(parts) != 3:
        raise OidcError("id_token провайдера не похож на JWT (не 3 части)")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        claims = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OidcError(f"id_token провайдера не разобрать: {exc}") from exc

    # Только RS256 — сознательно не читаем alg из "гибкого" списка и не
    # принимаем "none": классическая атака JWT alg-confusion (алгоритм
    # выбирает атакующий, не мы) исключена тем, что альтернативы просто
    # не поддержаны, а не отфильтрованы по allowlist из самого токена.
    if header.get("alg") != "RS256":
        raise OidcError(f"id_token подписан алгоритмом {header.get('alg')!r}, поддержан только RS256")

    doc = await _discovery()
    jwks_uri = doc.get("jwks_uri")
    if not jwks_uri:
        raise OidcError("OIDC discovery не содержит jwks_uri")
    jwks = await _jwks(jwks_uri)
    kid = header.get("kid")
    candidates = [
        key for key in jwks.get("keys", [])
        if key.get("kty") == "RSA" and (kid is None or key.get("kid") == kid)
    ]
    if not candidates:
        raise OidcError(f"в JWKS провайдера нет RSA-ключа с kid={kid!r} — id_token не проверить")

    signed_message = f"{header_b64}.{payload_b64}".encode("ascii")
    verified = False
    for jwk in candidates:
        try:
            public_key = _rsa_public_key_from_jwk(jwk)
            public_key.verify(signature, signed_message, padding.PKCS1v15(), hashes.SHA256())
            verified = True
            break
        except (InvalidSignature, KeyError, ValueError):
            continue
    if not verified:
        raise OidcError("подпись id_token не совпала ни с одним ключом из JWKS провайдера")

    now = time.time()
    exp = claims.get("exp")
    if exp is None or now > float(exp) + _CLOCK_SKEW_SECONDS:
        raise OidcError("id_token просрочен (exp)")
    iat = claims.get("iat")
    if iat is not None and float(iat) > now + _CLOCK_SKEW_SECONDS:
        raise OidcError("id_token выпущен в будущем (iat) — часы разошлись или токен подделан")

    token_issuer = claims.get("iss")
    if token_issuer != expected_issuer:
        raise OidcError(f"id_token.iss={token_issuer!r} не совпадает с настроенным issuer={expected_issuer!r}")

    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if expected_audience not in aud_list:
        raise OidcError(f"id_token.aud={aud!r} не содержит наш client_id={expected_audience!r}")
    # azp (authorized party) есть у части провайдеров (в т.ч. Keycloak),
    # когда aud шире одного client_id — если он присутствует, обязан
    # указывать на нас же, иначе токен, честно выпущенный для ДРУГОГО
    # клиента того же провайдера, прошёл бы только по общей aud.
    azp = claims.get("azp")
    if azp is not None and azp != expected_audience:
        raise OidcError(f"id_token.azp={azp!r} не совпадает с нашим client_id={expected_audience!r}")

    if not claims.get("sub"):
        raise OidcError("id_token без sub")

    return claims


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
    """Код → токены (token_endpoint) → userinfo (userinfo_endpoint) +
    независимая проверка id_token (см. verify_id_token и docstring
    модуля). userinfo остаётся источником профиля (preferred_username/
    email — их в id_token часто нет), но sub, которым мы заводим/находим
    локального User (см. sync_oidc_user), берётся из ПРОВЕРЕННОГО
    id_token, а не из непроверенного HTTP-ответа userinfo — при
    расхождении вход отклоняется."""
    doc = await _discovery()
    token_endpoint = doc.get("token_endpoint")
    userinfo_endpoint = doc.get("userinfo_endpoint")
    issuer = doc.get("issuer") or os.environ["GRIDFORGE_OIDC_ISSUER"].rstrip("/")
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

        id_token = tokens.get("id_token")
        if not id_token:
            # По OIDC Core 1.0 §3.1.3.3 id_token обязателен в ответе
            # Authorization Code Flow при scope=openid (у нас — всегда,
            # см. build_authorize_url) — отсутствие означает провайдер,
            # который этому не следует, и мы больше не можем независимо
            # подтвердить sub/iss/aud, поэтому отказываем, а не тихо
            # откатываемся на непроверенный userinfo.
            raise OidcError("ответ token_endpoint без id_token — провайдер не соответствует OIDC Core 1.0 §3.1.3.3")

        try:
            info_res = await client.get(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}"})
            info_res.raise_for_status()
            userinfo = info_res.json()
        except httpx.HTTPError as exc:
            raise OidcError(f"запрос userinfo не удался: {exc}") from exc

    id_claims = await verify_id_token(id_token, issuer, os.environ["GRIDFORGE_OIDC_CLIENT_ID"])
    userinfo_sub = userinfo.get("sub")
    if userinfo_sub != id_claims["sub"]:
        # userinfo_endpoint отвечает НЕ подписанным JSON — сервер/узел
        # между нами и провайдером мог бы подсунуть чужой sub. id_token
        # подписан провайдером, поэтому именно его sub — источник правды;
        # расхождение с userinfo — сигнал подмены, а не мелочь.
        raise OidcError(f"sub из userinfo ({userinfo_sub!r}) не совпадает с sub из id_token ({id_claims['sub']!r})")
    userinfo = dict(userinfo)
    userinfo["sub"] = id_claims["sub"]
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
