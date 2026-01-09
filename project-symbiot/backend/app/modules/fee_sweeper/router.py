from __future__ import annotations

import json
import secrets
from pathlib import Path
from fastapi import APIRouter, Depends

from app.api.schemas import FeeSweepRequest, FeeSweepResponse
from app.core.config import settings
from app.db.sqlite import SqliteDB, insert_fee_sweep
from app.modules.fee_sweeper.service import decide
from datetime import datetime, timezone

router = APIRouter(prefix="/sweeper", tags=["fee_sweeper"])

def get_db() -> SqliteDB:
    if not settings.DB_URI.startswith("sqlite:///"):
        raise RuntimeError("Only sqlite:/// is supported in this scaffold.")
    p = Path(settings.DB_URI.replace("sqlite:///", "", 1))
    return SqliteDB(path=p)

@router.post("/rebalance", response_model=FeeSweepResponse)
def rebalance(req: FeeSweepRequest, db: SqliteDB = Depends(get_db)) -> FeeSweepResponse:
    decision, audit = decide(req)

    sweep_id = "SW-" + secrets.token_hex(8)
    ts = datetime.now(timezone.utc).isoformat()

    conn = db.connect()
    try:
        insert_fee_sweep(
            conn,
            sweep_id=sweep_id,
            created_ts=ts,
            request_json=json.dumps(req.model_dump(), sort_keys=True),
            result_json=json.dumps({"decision": decision.model_dump(), "audit": audit}, sort_keys=True),
        )
    finally:
        conn.close()

    return FeeSweepResponse(
        sweep_id=sweep_id,
        timestamp_utc=ts,
        decision=decision,
        audit=audit,
    )
