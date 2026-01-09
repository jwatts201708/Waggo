from __future__ import annotations

import json
import logging
from fastapi import APIRouter, Depends
from pathlib import Path
from datetime import datetime, timezone

from app.api.schemas import NeuroStepRequest, NeuroStepResponse, NeuroGraphSnapshot
from app.modules.neuro_sync.service import NeuroGraph
from app.core.config import settings
from app.db.sqlite import SqliteDB, upsert_neuro_snapshot

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/neuro", tags=["neuro_sync"])

# In-memory graph + durable snapshots

_GRAPH = NeuroGraph()
_GRAPH.add_dense_edges()

def get_db() -> SqliteDB:
    # sqlite:///file.db
    if not settings.DB_URI.startswith("sqlite:///"):
        raise RuntimeError("Only sqlite:/// is supported in this scaffold.")
    p = Path(settings.DB_URI.replace("sqlite:///", "", 1))
    return SqliteDB(path=p)

@router.post("/step", response_model=NeuroStepResponse)
def step(req: NeuroStepRequest, db: SqliteDB = Depends(get_db)) -> NeuroStepResponse:
    snap = _GRAPH.step(req)

    conn = db.connect()
    try:
        nodes_json = json.dumps(snap.nodes)
        edges_json = json.dumps(snap.edges)
        upsert_neuro_snapshot(
            conn,
            snap_id=snap.snapshot_id,
            snapshot_ts=snap.timestamp_utc,
            nodes_json=nodes_json,
            edges_json=edges_json,
        )
    finally:
        conn.close()

    return NeuroStepResponse(snapshot=snap)

@router.get("/snapshot/latest", response_model=NeuroGraphSnapshot)
def latest_snapshot() -> NeuroGraphSnapshot:
    # returns current in-memory snapshot without DB read
    ts = datetime.now(timezone.utc).isoformat()
    nodes = {k: {"activation": v.activation, "bias": v.bias, "last_input": v.last_input} for k, v in _GRAPH.nodes.items()}
    edges = {f"{a}->{b}": {"weight": e.weight, "last_delta": e.last_delta} for (a, b), e in _GRAPH.edges.items()}
    return NeuroGraphSnapshot(snapshot_id="LIVE", timestamp_utc=ts, nodes=nodes, edges=edges)
