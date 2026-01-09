from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Dict, Tuple

from app.api.schemas import FeeSweepRequest, FeeSweepDecision

logger = logging.getLogger(__name__)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _usd_total(req: FeeSweepRequest) -> float:
    return sum(a.balance * a.usd_price for a in req.assets)

def _gas_usd(req: FeeSweepRequest) -> float:
    # gas_estimate_native is a native token amount; convert to USD using asset usd_price if symbol matches
    # for simplicity: assume each asset’s gas estimate is in its chain native token and priced by its usd_price
    # if you pass only native tokens as assets, this is accurate enough for the scaffold.
    return sum(a.gas_estimate_native * a.usd_price for a in req.assets)

def _effective_max_fee_gwei(req: FeeSweepRequest) -> float:
    # EIP-1559-ish: maxFeePerGas = (baseFee + priorityFee) * (1 + buffer%)
    buf = 1.0 + (req.gas_price_buffer_percent / 100.0)
    # take worst-case across assets
    return max((a.base_fee_gwei + a.priority_fee_gwei) * buf for a in req.assets) if req.assets else 0.0

def _gov_veto(policy_hash: str, estimated_total_usd: float) -> Tuple[bool, str]:
    # Governance hook: deterministic veto logic as a stand-in for DAO policy engine.
    # Example: veto if policy hash encodes “VETO” or if total is absurdly large without explicit policy.
    if "VETO" in policy_hash.upper():
        return True, "Governance veto flag present in policy hash."
    if estimated_total_usd > 100000 and "HIGHVALUE" not in policy_hash.upper():
        return True, "High-value sweep requires HIGHVALUE policy."
    return False, "No veto."

def _pqc_sign_sim(message: str) -> str:
    # Dilithium-ish simulation: returns hash + random salt.
    salt = secrets.token_hex(16)
    digest = hashlib.sha3_256((salt + "::" + message).encode()).hexdigest()
    return f"DILITHIUM_SIM:{digest}:{salt}"

def decide(req: FeeSweepRequest) -> Tuple[FeeSweepDecision, Dict[str, Any]]:
    total = _usd_total(req)
    gas = _gas_usd(req)
    eff_fee = _effective_max_fee_gwei(req)

    if total < req.min_sweep_threshold_usd:
        return FeeSweepDecision(
            should_sweep=False,
            reason=f"Below threshold: total_usd={total:.2f} < min={req.min_sweep_threshold_usd:.2f}",
            estimated_total_usd=total,
            estimated_gas_usd=gas,
            effective_max_fee_gwei=eff_fee,
        ), {"ts": _now(), "stage": "threshold"}

    veto, veto_reason = _gov_veto(req.governance_policy_hash, total)
    if veto:
        return FeeSweepDecision(
            should_sweep=False,
            reason=f"Governance veto: {veto_reason}",
            estimated_total_usd=total,
            estimated_gas_usd=gas,
            effective_max_fee_gwei=eff_fee,
        ), {"ts": _now(), "stage": "governance", "policy_hash": req.governance_policy_hash}

    # If gas cost is too high relative to value, reject
    if gas >= total * 0.25:
        return FeeSweepDecision(
            should_sweep=False,
            reason=f"Gas too high vs value: gas_usd={gas:.2f} >= 25% of total_usd={total:.2f}",
            estimated_total_usd=total,
            estimated_gas_usd=gas,
            effective_max_fee_gwei=eff_fee,
        ), {"ts": _now(), "stage": "economics"}

    # Approve
    msg = json.dumps(req.model_dump(), sort_keys=True)
    sig = _pqc_sign_sim(msg) if req.pqc_enforcement else None

    decision = FeeSweepDecision(
        should_sweep=True,
        reason="Approved: threshold met, no governance veto, gas economical.",
        estimated_total_usd=total,
        estimated_gas_usd=gas,
        effective_max_fee_gwei=eff_fee,
        pqc_signature_sim=sig,
    )
    audit = {
        "ts": _now(),
        "stage": "approved",
        "policy_hash": req.governance_policy_hash,
        "pqc_enforcement": req.pqc_enforcement,
    }
    logger.info("fee_sweep_decision", extra={"should_sweep": True, "total_usd": total, "gas_usd": gas})
    return decision, audit
