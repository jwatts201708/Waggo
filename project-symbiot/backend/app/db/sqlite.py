from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

@dataclass
class SqliteDB:
    path: Path

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path.as_posix(), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path.as_posix(), check_same_thread=False)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS neuro_graph (
                id TEXT PRIMARY KEY,
                snapshot_ts TEXT NOT NULL,
                nodes_json TEXT NOT NULL,
                edges_json TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS fee_sweeps (
                id TEXT PRIMARY KEY,
                created_ts TEXT NOT NULL,
                request_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            );
        """)
        conn.commit()
    finally:
        conn.close()

def upsert_neuro_snapshot(conn: sqlite3.Connection, *, snap_id: str, snapshot_ts: str, nodes_json: str, edges_json: str) -> None:
    conn.execute("""
        INSERT INTO neuro_graph(id, snapshot_ts, nodes_json, edges_json)
        VALUES(?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET snapshot_ts=excluded.snapshot_ts, nodes_json=excluded.nodes_json, edges_json=excluded.edges_json;
    """, (snap_id, snapshot_ts, nodes_json, edges_json))
    conn.commit()

def insert_fee_sweep(conn: sqlite3.Connection, *, sweep_id: str, created_ts: str, request_json: str, result_json: str) -> None:
    conn.execute("""
        INSERT INTO fee_sweeps(id, created_ts, request_json, result_json)
        VALUES(?,?,?,?);
    """, (sweep_id, created_ts, request_json, result_json))
    conn.commit()

def get_latest_neuro_snapshot(conn: sqlite3.Connection) -> Optional[Dict[str, Any]]:
    cur = conn.execute("""
        SELECT id, snapshot_ts, nodes_json, edges_json
        FROM neuro_graph
        ORDER BY snapshot_ts DESC
        LIMIT 1;
    """)
    row = cur.fetchone()
    if not row:
        return None
    return {"id": row[0], "snapshot_ts": row[1], "nodes_json": row[2], "edges_json": row[3]}
