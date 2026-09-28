"""Секреты канала (webhook-URL, bot_token) не должны лежать в БД открытым
текстом и не должны отдаваться наружу через API."""

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app.auth import generate_key
from app.main import app
from app.models import ApiKeyRole, Channel, ChannelKind, Incident, Node, Probe, ProbeKind, Watch, WatchOperator, WatchSeverity
from app.secrets_crypto import SECRET_MARKER
from app.signal import dispatch, encrypt_channel_config, mask_channel_config


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


@pytest.fixture()
def admin_key(db):
    return generate_key(db, label="test-admin", role=ApiKeyRole.admin)


def _h(key):
    return {"X-API-Key": key}


def test_encrypt_channel_config_hides_webhook_url():
    encrypted = encrypt_channel_config({"url": "https://hooks.slack.com/services/T000/B000/секрет"})
    assert encrypted["url"].startswith(SECRET_MARKER)
    assert "секрет" not in encrypted["url"]


def test_encrypt_channel_config_hides_bot_token():
    encrypted = encrypt_channel_config({"bot_token": "123:ABC", "chat_id": "42"})
    assert encrypted["bot_token"].startswith(SECRET_MARKER)
    assert encrypted["chat_id"] == "42"  # не секрет — остаётся как есть


def test_mask_shows_host_but_not_token():
    encrypted = encrypt_channel_config({"url": "https://hooks.slack.com/services/T000/B000/секрет"})
    masked = mask_channel_config(encrypted)
    assert masked["url_host"] == "hooks.slack.com"  # видно, куда шлёт
    assert "url" not in masked  # но сам адрес с токеном — нет
    assert "секрет" not in str(masked)


def test_stored_channel_has_no_plaintext_secret(client, admin_key, db):
    secret_url = "https://hooks.example.test/очень-секретный-путь"
    resp = client.post(
        "/api/channels",
        json={"kind": "webhook", "config": {"url": secret_url}},
        headers=_h(admin_key),
    )
    assert resp.status_code == 201

    stored = db.get(Channel, resp.json()["id"])
    db.refresh(stored)
    assert "очень-секретный-путь" not in str(stored.config)
    assert stored.config["url"].startswith(SECRET_MARKER)


def test_api_never_returns_channel_secret(client, admin_key):
    secret_url = "https://hooks.example.test/очень-секретный-путь"
    client.post("/api/channels", json={"kind": "webhook", "config": {"url": secret_url}}, headers=_h(admin_key))

    listed = client.get("/api/channels", headers=_h(admin_key)).json()
    assert "очень-секретный-путь" not in str(listed)
    assert listed[0]["config"]["url_host"] == "hooks.example.test"


class _RecordingClient:
    def __init__(self):
        self.calls = []

    async def post(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return httpx.Response(200)


def test_dispatch_sends_to_decrypted_url(db):
    """Главная проверка: зашифрованный в БД адрес должен расшифроваться
    при отправке — иначе доставка молча ушла бы на строку 'enc:...'."""
    node = Node(name="n", address="10.0.0.1")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="down")
    db.add(watch)
    db.commit()
    incident = Incident(watch_id=watch.id, detail="упал")
    db.add(incident)
    db.commit()
    db.refresh(incident)

    real_url = "https://hooks.example.test/путь"
    db.add(Channel(kind=ChannelKind.webhook, config=encrypt_channel_config({"url": real_url})))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident]))
    assert client.calls[0][0] == real_url


def test_legacy_plaintext_channel_still_works(db):
    """Каналы, заведённые до шифрования, лежат без маркера enc: —
    decrypt_secret пропускает их как есть, доставка не должна сломаться."""
    node = Node(name="n2", address="10.0.0.2")
    db.add(node)
    db.commit()
    probe = Probe(node_id=node.id, kind=ProbeKind.icmp_ping)
    db.add(probe)
    db.commit()
    watch = Watch(probe_id=probe.id, operator=WatchOperator.eq, severity=WatchSeverity.critical, label="down")
    db.add(watch)
    db.commit()
    incident = Incident(watch_id=watch.id, detail="упал")
    db.add(incident)
    db.commit()
    db.refresh(incident)

    db.add(Channel(kind=ChannelKind.webhook, config={"url": "http://старый.test/hook"}))
    db.commit()

    client = _RecordingClient()
    asyncio.run(dispatch(client, db, [incident]))
    assert client.calls[0][0] == "http://старый.test/hook"
