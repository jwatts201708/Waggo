from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.utils.logging import setup_logging
from app.db.sqlite import init_db

from app.modules.neuro_sync.router import router as neuro_router
from app.modules.quantum.router import router as quantum_router
from app.modules.fee_sweeper.router import router as sweeper_router
from app.api.schemas import HealthResponse

logger = logging.getLogger(__name__)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def create_app() -> FastAPI:
    setup_logging("INFO")

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=f"{settings.KERNEL_VERSION}+{settings.SWEEPER_VERSION}",
    )

    # CORS for local static frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # DB init (SQLite)
    if settings.DB_URI.startswith("sqlite:///"):
        db_path = Path(settings.DB_URI.replace("sqlite:///", "", 1))
        init_db(db_path)
        logger.info("db_initialized", extra={"db_path": db_path.as_posix()})

    app.include_router(neuro_router)
    app.include_router(quantum_router)
    app.include_router(sweeper_router)

    @app.get("/health", response_model=HealthResponse, tags=["system"])
    def health() -> HealthResponse:
        return HealthResponse(
            project=settings.PROJECT_NAME,
            codex_id=settings.CODEX_ID,
            kernel_version=settings.KERNEL_VERSION,
            sweeper_version=settings.SWEEPER_VERSION,
            timestamp_utc=utc_now(),
        )

    return app

app = create_app()
