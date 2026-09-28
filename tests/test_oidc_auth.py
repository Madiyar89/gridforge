"""Вход через OIDC SSO (app/oidc_auth.py) — упор на то, из-за чего этот
модуль правили 2026-09-28: id_token теперь подписывается провайдером
(RS256) и проверяется самостоятельно (подпись + iss/aud), а sub для
локального User берётся из ПРОВЕРЕННОГО id_token, а не из непроверенного
userinfo. Настоящего Keycloak в тестах нет — HTTP-вызовы к discovery/
token/userinfo/jwks подменяются (тот же приём, что test_ad_auth.py
применяет к LDAP-bind), но JWT подписываются настоящим RSA-ключом, чтобы
проверить настоящую криптографию, а не просто вызов функции.

Async-функции модуля запускаются через asyncio.run() внутри обычных
sync-тестов — в проекте нет pytest-asyncio/anyio-плагина, а тащить его
только для этого файла не стоит: asyncio.run — стандартная библиотека."""

from __future__ import annotations

import asyncio
import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app import oidc_auth
from app.oidc_auth import OidcError, exchange_code_for_userinfo, verify_id_token

ISSUER = "https://keycloak.test/realms/gridforge"
CLIENT_ID = "gridforge-client"
TOKEN_ENDPOINT = f"{ISSUER}/protocol/openid-connect/token"
USERINFO_ENDPOINT = f"{ISSUER}/protocol/openid-connect/userinfo"
JWKS_URI = f"{ISSUER}/protocol/openid-connect/certs"
KID = "test-key-1"


def run(coro):
    return asyncio.run(coro)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _rsa_keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _jwk_from_public_key(public_key, kid: str) -> dict:
    numbers = public_key.public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": _b64url(n), "e": _b64url(e)}


def _sign_id_token(private_key, claims: dict, kid: str | None = KID, alg: str = "RS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(claims).encode())
    signed_message = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signed_message, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


@pytest.fixture()
def keypair():
    return _rsa_keypair()


@pytest.fixture()
def base_claims():
    now = time.time()
    return {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "11111111-1111-1111-1111-111111111111",
        "exp": now + 300,
        "iat": now,
    }


@pytest.fixture()
def oidc_configured(monkeypatch):
    monkeypatch.setenv("GRIDFORGE_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("GRIDFORGE_OIDC_CLIENT_ID", CLIENT_ID)
    oidc_auth._discovery_cache.clear()
    oidc_auth._jwks_cache.clear()
    yield
    oidc_auth._discovery_cache.clear()
    oidc_auth._jwks_cache.clear()


@pytest.fixture()
def fake_discovery_and_jwks(monkeypatch, oidc_configured):
    """Подменяет _discovery на фиксированный документ (issuer + jwks_uri)
    и предзаполняет кэш JWKS данным набором ключей — для тестов
    verify_id_token(), которым не нужен весь HTTP-обмен кода на токен."""

    async def fake_discovery():
        return {"issuer": ISSUER, "jwks_uri": JWKS_URI}

    monkeypatch.setattr(oidc_auth, "_discovery", fake_discovery)

    def _apply(jwks_keys: list[dict]):
        oidc_auth._jwks_cache[JWKS_URI] = (time.monotonic(), {"keys": jwks_keys})

    return _apply


def _mock_transport(*, id_token: str | None, userinfo_sub: str, jwks_keys: list[dict], access_token: str = "at-123"):
    """httpx-транспорт без сети: раздаёт discovery/token/userinfo/jwks по
    URL — тот же приём подмены, что monkeypatch делает для LDAP в
    test_ad_auth.py, но на уровне HTTP-транспорта httpx (сам httpx не
    даёт хука на уровне отдельных функций, только на уровне клиента)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ISSUER,
                "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
                "token_endpoint": TOKEN_ENDPOINT,
                "userinfo_endpoint": USERINFO_ENDPOINT,
                "jwks_uri": JWKS_URI,
            })
        if url == TOKEN_ENDPOINT:
            body = {"access_token": access_token, "token_type": "Bearer"}
            if id_token is not None:
                body["id_token"] = id_token
            return httpx.Response(200, json=body)
        if url == USERINFO_ENDPOINT:
            return httpx.Response(200, json={
                "sub": userinfo_sub,
                "preferred_username": "ivanov",
                "email": "ivanov@corp.test",
            })
        if url == JWKS_URI:
            return httpx.Response(200, json={"keys": jwks_keys})
        return httpx.Response(404, json={"error": "unexpected url in test transport", "url": url})

    return httpx.MockTransport(handler)


@pytest.fixture()
def patch_httpx_client(monkeypatch):
    """Подменяет httpx.AsyncClient так, чтобы все клиенты, создаваемые
    внутри oidc_auth (discovery/token/userinfo/jwks — разные async with
    блоки), использовали переданный MockTransport вместо реальной сети."""

    def _apply(transport: httpx.MockTransport):
        real_async_client = httpx.AsyncClient

        class _PatchedAsyncClient(real_async_client):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = transport
                super().__init__(*args, **kwargs)

        monkeypatch.setattr(oidc_auth.httpx, "AsyncClient", _PatchedAsyncClient)

    return _apply


def test_valid_id_token_matches_userinfo_sub_passes(oidc_configured, patch_httpx_client, keypair, base_claims):
    """Регрессия: полный сценарий (правильные iss/aud, подпись валидным
    ключом, sub совпадает с userinfo) должен продолжать работать, как и
    до добавления проверки id_token."""
    private_key, public_key = keypair
    id_token = _sign_id_token(private_key, base_claims)
    transport = _mock_transport(
        id_token=id_token,
        userinfo_sub=base_claims["sub"],
        jwks_keys=[_jwk_from_public_key(public_key, KID)],
    )
    patch_httpx_client(transport)

    userinfo = run(exchange_code_for_userinfo("auth-code", "verifier", "https://gridforge.test/auth/oidc/callback"))

    assert userinfo["sub"] == base_claims["sub"]
    assert userinfo["preferred_username"] == "ivanov"


def test_wrong_issuer_rejected(fake_discovery_and_jwks, keypair, base_claims):
    private_key, public_key = keypair
    claims = dict(base_claims, iss="https://evil.example/realms/other")
    id_token = _sign_id_token(private_key, claims)
    fake_discovery_and_jwks([_jwk_from_public_key(public_key, KID)])

    with pytest.raises(OidcError, match="iss"):
        run(verify_id_token(id_token, ISSUER, CLIENT_ID))


def test_wrong_audience_rejected(fake_discovery_and_jwks, keypair, base_claims):
    private_key, public_key = keypair
    claims = dict(base_claims, aud="some-other-client")
    id_token = _sign_id_token(private_key, claims)
    fake_discovery_and_jwks([_jwk_from_public_key(public_key, KID)])

    with pytest.raises(OidcError, match="aud"):
        run(verify_id_token(id_token, ISSUER, CLIENT_ID))


def test_wrong_signing_key_rejected(fake_discovery_and_jwks, keypair, base_claims):
    """id_token подписан ДРУГИМ приватным ключом (не тем, что в JWKS
    провайдера под тем же kid) — атака "подставной токен" должна
    отклоняться на этапе проверки подписи, а не пройти по одним claims."""
    _, real_public_key = keypair
    attacker_private_key, _ = _rsa_keypair()
    id_token = _sign_id_token(attacker_private_key, base_claims)
    fake_discovery_and_jwks([_jwk_from_public_key(real_public_key, KID)])

    with pytest.raises(OidcError, match="подпись"):
        run(verify_id_token(id_token, ISSUER, CLIENT_ID))


def test_unsupported_alg_rejected(fake_discovery_and_jwks, keypair, base_claims):
    """alg=HS256 (или "none") должен отбрасываться до любой попытки
    проверки подписи — защита от alg-confusion."""
    private_key, public_key = keypair
    id_token = _sign_id_token(private_key, base_claims, alg="HS256")
    fake_discovery_and_jwks([_jwk_from_public_key(public_key, KID)])

    with pytest.raises(OidcError, match="RS256"):
        run(verify_id_token(id_token, ISSUER, CLIENT_ID))


def test_expired_id_token_rejected(fake_discovery_and_jwks, keypair, base_claims):
    private_key, public_key = keypair
    claims = dict(base_claims, exp=time.time() - 3600, iat=time.time() - 7200)
    id_token = _sign_id_token(private_key, claims)
    fake_discovery_and_jwks([_jwk_from_public_key(public_key, KID)])

    with pytest.raises(OidcError, match="просрочен"):
        run(verify_id_token(id_token, ISSUER, CLIENT_ID))


def test_userinfo_sub_mismatch_rejected(oidc_configured, patch_httpx_client, keypair, base_claims):
    """id_token валиден (правильные iss/aud/подпись), но userinfo вернул
    ДРУГОЙ sub — сигнал подмены userinfo-ответа (не подписан, в отличие
    от id_token). Должно отклоняться на уровне exchange_code_for_userinfo,
    не проходить как есть."""
    private_key, public_key = keypair
    id_token = _sign_id_token(private_key, base_claims)
    transport = _mock_transport(
        id_token=id_token,
        userinfo_sub="22222222-2222-2222-2222-222222222222",  # не совпадает с base_claims["sub"]
        jwks_keys=[_jwk_from_public_key(public_key, KID)],
    )
    patch_httpx_client(transport)

    with pytest.raises(OidcError, match="sub"):
        run(exchange_code_for_userinfo("auth-code", "verifier", "https://gridforge.test/auth/oidc/callback"))


def test_missing_id_token_rejected(oidc_configured, patch_httpx_client, keypair, base_claims):
    """Провайдер не прислал id_token вовсе (не соответствует OIDC Core
    1.0 §3.1.3.3 для scope=openid) — раньше это тихо принималось (только
    userinfo), теперь должно отклоняться явной ошибкой."""
    _, public_key = keypair
    transport = _mock_transport(
        id_token=None,
        userinfo_sub=base_claims["sub"],
        jwks_keys=[_jwk_from_public_key(public_key, KID)],
    )
    patch_httpx_client(transport)

    with pytest.raises(OidcError, match="id_token"):
        run(exchange_code_for_userinfo("auth-code", "verifier", "https://gridforge.test/auth/oidc/callback"))
