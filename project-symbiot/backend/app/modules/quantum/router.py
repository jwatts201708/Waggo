from __future__ import annotations

from fastapi import APIRouter
from app.api.schemas import QuantumKeyRequest, QuantumKeyResponse
from app.modules.quantum.service import QuantumLink

router = APIRouter(prefix="/quantum", tags=["quantumlink"])

_QL = QuantumLink()

@router.post("/derive-key", response_model=QuantumKeyResponse)
def derive_key(req: QuantumKeyRequest) -> QuantumKeyResponse:
    key, audit = _QL.derive_shared_key(req.alice, req.bob, req.basis_seed)
    return QuantumKeyResponse(shared_key_hex=key, audit=audit)
