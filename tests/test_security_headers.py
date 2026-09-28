"""CSP-заголовок — страховка против будущей XSS-регрессии (сам код на
момент правки отдельным аудитом не показал активной дыры), см. комментарий
у add_csp_header в app/main.py."""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture()
def client():
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def test_csp_header_present_on_api_response(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200
    csp = resp.headers.get('content-security-policy')
    assert csp is not None
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_csp_header_present_on_static_response(client):
    resp = client.get('/login.html')
    assert resp.status_code == 200
    assert resp.headers.get('content-security-policy') is not None


def test_csp_forbids_unsafe_inline_scripts(client):
    """script-src не должен разрешать инлайн-скрипты — весь фронтенд
    грузит JS через <script src=...> с того же origin, инлайн не нужен."""
    resp = client.get('/api/health')
    csp = resp.headers['content-security-policy']
    script_src = [p.strip() for p in csp.split(';') if p.strip().startswith('script-src')][0]
    assert "'unsafe-inline'" not in script_src
