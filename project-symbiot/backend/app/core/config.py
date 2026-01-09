from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "Project Symbiot - Unified Omnichannel Protocol"
    CODEX_ID: str = "SYMBIOT_KERNEL_V19_V21"
    KERNEL_VERSION: str = "19.0.0-FINAL-SYNTHESIS"
    SWEEPER_VERSION: str = "21.0.0-FEE-OPTIMIZER"

    DB_URI: str = Field(default="sqlite:///symbiot_v19_final.db")
    GLOBAL_AI_RISK_CAP: float = Field(default=0.12)

    # Fee Sweeper config
    MIN_SWEEP_THRESHOLD_USD: float = Field(default=50.0)
    GAS_PRICE_BUFFER_PERCENT: float = Field(default=15.0)
    PQC_ENFORCEMENT: bool = Field(default=True)

settings = Settings()
