from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

@dataclass
class QuantumLink:
    """
    Functional simulation: not real quantum.
    Treats "entanglement" as shared entropy negotiation + basis mismatch filtering.
    Produces a shared key by hashing agreed bits.
    """

    def derive_shared_key(self, alice: str, bob: str, basis_seed: int | None = None) -> Tuple[str, Dict[str, Any]]:
        seed = basis_seed if basis_seed is not None else secrets.randbelow(2**31 - 1)

        # Derive pseudo-random bitstreams per party from seed + identity
        a_stream = hashlib.sha256(f"{seed}:{alice}".encode()).digest()
        b_stream = hashlib.sha256(f"{seed}:{bob}".encode()).digest()

        # Each party also "chooses bases"
        a_basis = hashlib.sha256(f"basis:{seed}:{alice}".encode()).digest()
        b_basis = hashlib.sha256(f"basis:{seed}:{bob}".encode()).digest()

        agreed_bits = []
        for i in range(32):
            # basis agreement when lowest bit matches
            if (a_basis[i] & 1) == (b_basis[i] & 1):
                # take one bit from each and xor them
                bit = ((a_stream[i] & 1) ^ (b_stream[i] & 1)) & 1
                agreed_bits.append(bit)

        # Collapse: hash agreed bits into key
        bitstring = "".join(str(b) for b in agreed_bits).encode()
        shared_key = hashlib.sha256(bitstring).hexdigest()

        audit = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "seed": seed,
            "agreed_bits": len(agreed_bits),
            "note": "Simulation only. Do not treat as cryptographic quantum security.",
        }
        logger.info("quantumlink_key_derived", extra={"seed": seed, "agreed_bits": len(agreed_bits)})
        return shared_key, audit
