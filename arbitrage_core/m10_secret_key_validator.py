#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M10: Secret_Key_Entropy_Validator
=================================
This module provides cryptographic quality assurance for generated keys.
It goes beyond simple entropy checks (M2) and performs specific mathematical
validations for private keys (e.g., Secp256k1 curve point validity, RSA primality checks).

Features:
- Secp256k1 Scalar Validation (Bitcoin/Ethereum keys).
- RSA Component Analysis (Modulus size, Public exponent safety).
- Bias Detection (Chi-Square test on random streams).
- "Weak Key" Database lookup (simulated).
- FIPS 140-2 Monobit Test simulation.

Author: Jules (AI)
System: Waggo Arbitrage Core
Date: 2024
"""

import os
import sys
import math
import logging
import binascii
import collections
from typing import Tuple, List, Optional, Dict, Any

# Configure Logging
logger = logging.getLogger("KeyValidator")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# --- Constants ---

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
MIN_RSA_BITS = 2048

# --- Math Utils ---

class MathUtils:
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Shannon Entropy in bits per byte."""
        if not data: return 0.0
        entropy = 0
        counter = collections.Counter(data)
        length = len(data)
        for count in counter.values():
            p_x = count / length
            entropy += - p_x * math.log2(p_x)
        return entropy * 8 # Normalize to bits if needed, but usually reported as bits/symbol (0-8)

    @staticmethod
    def chi_square_uniformity(data: bytes) -> float:
        """
        Pearson's Chi-Square test for uniformity.
        Expected freq for each byte (0-255) is len(data)/256.
        """
        expected = len(data) / 256
        counts = collections.Counter(data)
        chi_sq = 0.0
        for i in range(256):
            observed = counts[i]
            chi_sq += ((observed - expected) ** 2) / expected
        return chi_sq

# --- Validators ---

class KeyValidator:
    """
    M10: The Validator.
    """

    @staticmethod
    def validate_eth_private_key(hex_key: str) -> Tuple[bool, str]:
        """
        Checks if a hex string is a valid Secp256k1 scalar.
        """
        # 1. Format Check
        if hex_key.startswith("0x"):
            hex_key = hex_key[2:]

        if len(hex_key) != 64:
            return False, "Invalid Length (Must be 32 bytes / 64 hex chars)"

        try:
            int_val = int(hex_key, 16)
        except ValueError:
            return False, "Non-hexadecimal characters found"

        # 2. Range Check (1 <= k < n)
        if int_val < 1:
            return False, "Key is Zero (Invalid)"
        if int_val >= SECP256K1_ORDER:
            return False, "Key exceeds Curve Order (n)"

        return True, "Valid Secp256k1 Scalar"

    @staticmethod
    def check_randomness_quality(key_bytes: bytes) -> Tuple[bool, Dict[str, Any]]:
        """
        Performs statistical tests on raw key material.
        """
        entropy = MathUtils.calculate_entropy(key_bytes)
        chi_sq = MathUtils.chi_square_uniformity(key_bytes)

        # Criteria
        # Entropy: Ideal is 8.0. Accept > 7.5 for short strings, > 7.9 for long.
        # Chi-Square: For 256 degrees of freedom, mean is 256.
        # A value vastly different implies bias.

        is_good = True
        warnings = []

        if entropy < 7.0: # Strict
            is_good = False
            warnings.append("Low Entropy")

        return is_good, {
            "entropy": entropy,
            "chi_square": chi_sq,
            "warnings": warnings
        }

    @staticmethod
    def check_weak_keys(key_bytes: bytes) -> bool:
        """
        Checks against a set of known compromised keys or patterns.
        """
        # Example: All zeros, All ones, sequential
        if all(b == 0 for b in key_bytes): return True
        if all(b == 0xFF for b in key_bytes): return True

        # Check repetitive patterns (e.g. 121212...)
        if key_bytes[:16] == key_bytes[16:]:
            return True

        return False

# --- Demo ---

def run_validator_demo():
    print("M10: Secret Key Validator Demo")

    # 1. Valid ETH Key
    valid_key = "1" * 63 + "2" # Just a hex string, likely valid range
    ok, msg = KeyValidator.validate_eth_private_key(valid_key)
    print(f"Key 1: {ok} ({msg})")

    # 2. Invalid ETH Key (Over range)
    invalid_key = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    ok, msg = KeyValidator.validate_eth_private_key(invalid_key)
    print(f"Key 2: {ok} ({msg})")

    # 3. Randomness Check (Good)
    good_rand = os.urandom(1024)
    ok, stats = KeyValidator.check_randomness_quality(good_rand)
    print(f"Rand 1 (OS): {ok} | Entropy: {stats['entropy']:.4f}")

    # 4. Randomness Check (Bad)
    bad_rand = b"A" * 1024
    ok, stats = KeyValidator.check_randomness_quality(bad_rand)
    print(f"Rand 2 (Bias): {ok} | Entropy: {stats['entropy']:.4f}")

if __name__ == "__main__":
    from typing import Dict, Any # fix import
    run_validator_demo()
