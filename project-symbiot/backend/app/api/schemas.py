from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Dict, List, Optional, Any

class HealthResponse(BaseModel):
    project: str
    codex_id: str
    kernel_version: str
    sweeper_version: str
    timestamp_utc: str

# NeuroSync

class NeuroSyncConfig(BaseModel):
    learning_rate: float = Field(default=0.05, ge=0.0, le=1.0)
    decay: float = Field(default=0.001, ge=0.0, le=1.0)
    propagation_steps: int = Field(default=3, ge=1, le=50)

class NeuroStimulus(BaseModel):
    node_id: str = Field(min_length=1, max_length=128)
    value: float = Field(default=1.0)

class NeuroStepRequest(BaseModel):
    config: NeuroSyncConfig = Field(default_factory=NeuroSyncConfig)
    stimuli: List[NeuroStimulus] = Field(default_factory=list)

class NeuroGraphSnapshot(BaseModel):
    snapshot_id: str
    timestamp_utc: str
    nodes: Dict[str, Dict[str, Any]]
    edges: Dict[str, Dict[str, Any]]

class NeuroStepResponse(BaseModel):
    snapshot: NeuroGraphSnapshot

# QuantumLink

class QuantumKeyRequest(BaseModel):
    alice: str = Field(min_length=1, max_length=64)
    bob: str = Field(min_length=1, max_length=64)
    basis_seed: Optional[int] = Field(default=None)

class QuantumKeyResponse(BaseModel):
    shared_key_hex: str
    audit: Dict[str, Any]

# Fee Sweeper

class FeeSweepAsset(BaseModel):
    chain: str = Field(min_length=1, max_length=32)
    symbol: str = Field(min_length=1, max_length=16)
    balance: float = Field(ge=0.0)
    usd_price: float = Field(ge=0.0)
    gas_estimate_native: float = Field(ge=0.0)
    base_fee_gwei: float = Field(ge=0.0)
    priority_fee_gwei: float = Field(ge=0.0)

class FeeSweepRequest(BaseModel):
    assets: List[FeeSweepAsset]
    min_sweep_threshold_usd: float = Field(default=50.0, ge=0.0)
    gas_price_buffer_percent: float = Field(default=15.0, ge=0.0, le=200.0)
    pqc_enforcement: bool = Field(default=True)
    governance_policy_hash: str = Field(default="GOV-POLICY-DEFAULT", min_length=1, max_length=128)

class FeeSweepDecision(BaseModel):
    should_sweep: bool
    reason: str
    estimated_total_usd: float
    estimated_gas_usd: float
    effective_max_fee_gwei: float
    pqc_signature_sim: Optional[str] = None

class FeeSweepResponse(BaseModel):
    sweep_id: str
    timestamp_utc: str
    decision: FeeSweepDecision
    audit: Dict[str, Any]
