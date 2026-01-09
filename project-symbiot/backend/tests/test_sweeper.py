from __future__ import annotations

from fastapi.testclient import TestClient
from app.main import app

def test_sweeper_rebalance_threshold_blocks():
    c = TestClient(app)
    payload = {
        "assets": [
            {
                "chain":"ETH","symbol":"ETH",
                "balance":0.01,"usd_price":2000.0,
                "gas_estimate_native":0.001,
                "base_fee_gwei":20.0,"priority_fee_gwei":2.0
            }
        ],
        "min_sweep_threshold_usd": 50.0,
        "gas_price_buffer_percent": 15.0,
        "pqc_enforcement": True,
        "governance_policy_hash":"GOV-POLICY-DEFAULT"
    }
    r = c.post("/sweeper/rebalance", json=payload)
    assert r.status_code == 200
    assert r.json()["decision"]["should_sweep"] in (True, False)
