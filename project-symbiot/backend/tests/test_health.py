from __future__ import annotations

from fastapi.testclient import TestClient
from app.main import app

def test_health_ok():
    c = TestClient(app)
    r = c.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert "project" in data
    assert "codex_id" in data
