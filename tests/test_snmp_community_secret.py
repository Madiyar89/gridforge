"""SNMP community string — тот же пробел, что был у Probe.params.password
до secrets_crypto (см. test_secrets_crypto.py/test_channel_secrets.py):
лежал в БД открытым текстом, хотя SSH-пароль на том же Probe уже шёл через
шифрование. Community шифруется при создании Probe (main.create_probe) и
расшифровывается в probes._build_snmp_auth перед SNMP-запросом — те же
encrypt_secret/decrypt_secret, тот же маркер enc:, что у password/
auth_password/priv_password."""

import asyncio

import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Node, Probe, ProbeKind
from app.probes import _build_snmp_auth
from app.secrets_crypto import SECRET_MARKER, decrypt_secret, encrypt_secret


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


def _h(key):
    return {"X-API-Key": key}


@pytest.fixture()
def node(db):
    n = Node(name="switch-1", address="10.0.0.5")
    db.add(n)
    db.commit()
    db.refresh(n)
    return n


def test_community_is_encrypted_on_probe_create(client, admin_key, db, node):
    resp = client.post(
        "/api/probes",
        json={
            "node_id": node.id,
            "kind": "snmp_get",
            "params": {"oid": "1.3.6.1.2.1.1.3.0", "community": "секретная-строка"},
        },
        headers=_h(admin_key),
    )
    assert resp.status_code == 201

    stored = db.get(Probe, resp.json()["id"])
    db.refresh(stored)
    assert stored.params["community"].startswith(SECRET_MARKER)
    assert "секретная-строка" not in str(stored.params)
    assert decrypt_secret(stored.params["community"]) == "секретная-строка"


def test_default_community_not_forced_through_encryption(client, admin_key, db, node):
    """Если community вообще не передан — params.get("community", "public")
    даёт дефолт при чтении, а не при записи; в params его может не быть
    вовсе, и это не должно ломать создание Probe."""
    resp = client.post(
        "/api/probes",
        json={"node_id": node.id, "kind": "snmp_get", "params": {"oid": "1.3.6.1.2.1.1.3.0"}},
        headers=_h(admin_key),
    )
    assert resp.status_code == 201
    stored = db.get(Probe, resp.json()["id"])
    db.refresh(stored)
    assert "community" not in stored.params


def test_snmp_executor_decrypts_stored_community():
    """_build_snmp_auth — общая точка чтения community у snmp_get/
    snmp_walk/snmp_counter_rate. Проверяем, что она отдаёт CommunityData с
    расшифрованным значением, а не сырым enc:-токеном."""
    params = {"community": encrypt_secret("реальная-community"), "version": "2c"}
    auth, error = _build_snmp_auth(params)
    assert error is None
    assert str(auth.communityName) == "реальная-community"


def test_legacy_plaintext_community_still_works():
    """Probe, заведённые до этого фикса — community без enc:-маркера.
    decrypt_secret пропускает такие значения как есть (тот же принцип,
    что и у legacy plaintext password/webhook — см.
    test_secrets_crypto.test_decrypt_passthrough_for_legacy_plaintext)."""
    params = {"community": "старая-открытая-строка", "version": "2c"}
    auth, error = _build_snmp_auth(params)
    assert error is None
    assert str(auth.communityName) == "старая-открытая-строка"


def test_snmp_get_probe_run_uses_decrypted_community():
    """От API до исполнителя: run_probe должен передать в pysnmp
    расшифрованную community, а не enc:-токен из params."""
    from app.models import ProbeKind as PK
    from app import probes

    captured = {}

    async def fake_get_cmd(engine, auth, target, context, obj_type):
        captured["community"] = str(auth.communityName)
        return None, None, 0, [(None, _FakeValue("42"))]

    class _FakeValue:
        def __init__(self, text):
            self._text = text

        def prettyPrint(self):
            return self._text

    with patch.object(probes, "get_cmd", AsyncMock(side_effect=fake_get_cmd)):
        outcome = asyncio.run(
            probes.run_probe(
                PK.snmp_get,
                "127.0.0.1",
                {"oid": "1.3.6.1.2.1.1.3.0", "community": encrypt_secret("живая-community")},
                1.0,
            )
        )
    assert outcome.ok
    assert captured["community"] == "живая-community"
