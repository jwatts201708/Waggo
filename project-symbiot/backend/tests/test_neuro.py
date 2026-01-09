from __future__ import annotations

from fastapi.testclient import TestClient
from app.main import app

def test_neuro_step():
    c = TestClient(app)
    payload = {
        "config": {"learning_rate": 0.05, "decay": 0.001, "propagation_steps": 2},
        "stimuli": [{"node_id": "sense", "value": 1.0}]
    }
    r = c.post("/neuro/step", json=payload)
    assert r.status_code == 200
    snap = r.json()["snapshot"]
    assert "nodes" in snap
    assert "edges" in snap
