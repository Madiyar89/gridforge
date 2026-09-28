"""Границы, которые не даёт нарушить хаб недоверенной площадке
(POST /api/sync/report — единственная точка, где хаб принимает данные
от сетевого узла, а не от своего же админа, см. app/schemas.py:
SyncReportIn/SyncIncidentIn и app/sync_engine.py:record_report)."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.sync_engine import MAX_INCIDENTS_IN_REPORT, create_site


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def site_token(db):
    _site, raw_token = create_site(db, "test-site")
    return raw_token


def _headers(token):
    return {"X-Sync-Token": token}


def _incident(node="core-sw1", watch_label="ping down", severity="critical", opened_at="2026-09-28T10:00:00"):
    return {"node": node, "watch_label": watch_label, "severity": severity, "opened_at": opened_at}


def test_normal_report_accepted(client, site_token):
    payload = {
        "label": "площадка-1",
        "node_count": 12,
        "incidents_critical": 1,
        "incidents_warning": 0,
        "incidents_info": 0,
        "incidents": [_incident()],
    }
    resp = client.post("/api/sync/report", json=payload, headers=_headers(site_token))
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_unknown_token_rejected_with_401(client):
    payload = {"label": "x", "node_count": 0, "incidents": []}
    resp = client.post("/api/sync/report", json=payload, headers=_headers("garbage-token"))
    assert resp.status_code == 401


def test_oversized_incident_field_rejected_with_422(client, site_token):
    payload = {
        "label": "площадка-1",
        "node_count": 1,
        "incidents": [_incident(node="A" * 500)],
    }
    resp = client.post("/api/sync/report", json=payload, headers=_headers(site_token))
    assert resp.status_code == 422


def test_oversized_top_level_label_rejected_with_422(client, site_token):
    payload = {"label": "L" * 1000, "node_count": 1, "incidents": []}
    resp = client.post("/api/sync/report", json=payload, headers=_headers(site_token))
    assert resp.status_code == 422


def test_too_many_incidents_still_truncated_not_rejected(client, site_token, db):
    from app.models import RemoteSiteReport

    count_within_schema_bound = MAX_INCIDENTS_IN_REPORT + 30  # больше 50, но меньше max_length=200 у схемы
    payload = {
        "label": "площадка-1",
        "node_count": 1,
        "incidents": [_incident(node=f"node-{i}") for i in range(count_within_schema_bound)],
    }
    resp = client.post("/api/sync/report", json=payload, headers=_headers(site_token))
    assert resp.status_code == 200

    stored = db.query(RemoteSiteReport).order_by(RemoteSiteReport.received_at.desc()).first()
    assert len(stored.incidents) == MAX_INCIDENTS_IN_REPORT


def test_way_too_many_incidents_rejected_with_422(client, site_token):
    """Список инцидентов сам по себе ограничен (max_length=200 на
    SyncReportIn.incidents) — площадка не может прислать миллион
    строк и заставить хаб распарсить/провалидировать их все."""
    payload = {
        "label": "площадка-1",
        "node_count": 1,
        "incidents": [_incident(node=f"node-{i}") for i in range(500)],
    }
    resp = client.post("/api/sync/report", json=payload, headers=_headers(site_token))
    assert resp.status_code == 422
