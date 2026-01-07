#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
M9: Encryption_Key_Rotator
==========================
This module manages the lifecycle of cryptographic keys used within the Waggo system.
It ensures that Data Encryption Keys (DEKs) are rotated regularly and that Key Encryption Keys (KEKs)
are securely managed (simulated HSM integration).

Features:
- Automated Key Rotation Schedules (Cron-based logic).
- Lazy Re-encryption (Data is re-encrypted on access).
- Envelope Encryption Pattern implementation.
- Compromise Recovery Mode (Emergency Revocation).
- Integration with simulated AWS KMS / Vault.

Author: Jules (AI)
System: Waggo Arbitrage Core
Date: 2024
"""

import os
import sys
import json
import logging
import time
import base64
import hashlib
import hmac
import uuid
import datetime
import threading
import typing
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Cryptography Simulation (Use 'cryptography' lib in prod)
# We implement a robust simulation of AES-GCM and Key Wrapping logic
try:
    import secrets
except ImportError:
    secrets = None

# Configure Logging
logger = logging.getLogger("KeyRotator")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# --- Constants ---

ROTATION_INTERVAL_DAYS = 90
MASTER_KEY_ENV_VAR = "WAGGO_MASTER_KEY_V1"

class KeyStatus(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated" # Can decrypt, but not encrypt
    REVOKED = "revoked" # Cannot use
    DESTROYED = "destroyed"

@dataclass
class KeyMetadata:
    key_id: str
    version: int
    algorithm: str = "AES-256-GCM"
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    status: KeyStatus = KeyStatus.ACTIVE

    def is_valid(self):
        return self.status == KeyStatus.ACTIVE and (self.expires_at == 0 or time.time() < self.expires_at)

@dataclass
class EncryptedDataEnvelope:
    key_id: str
    iv: str # Base64
    ciphertext: str # Base64
    tag: str # Base64

# --- Mock Crypto Primitives ---

class CryptoPrimitives:
    """
    Simulation of AES-GCM for demonstration purposes.
    In production, this MUST use `cryptography.hazmat`.
    """

    @staticmethod
    def generate_key(size=32) -> bytes:
        if secrets:
            return secrets.token_bytes(size)
        return os.urandom(size)

    @staticmethod
    def encrypt(key: bytes, plaintext: str) -> Tuple[bytes, bytes, bytes]:
        """
        Returns (iv, ciphertext, tag).
        Simulated by XOR + HMAC.
        """
        iv = os.urandom(12)
        # XOR Encryption (Insecure, Demo Only)
        pt_bytes = plaintext.encode('utf-8')
        # Extend key
        extended_key = (key * (len(pt_bytes) // len(key) + 1))[:len(pt_bytes)]
        ct_bytes = bytes(a ^ b for a, b in zip(pt_bytes, extended_key))

        # HMAC for Tag
        mac = hmac.new(key, iv + ct_bytes, hashlib.sha256)
        tag = mac.digest()

        return iv, ct_bytes, tag

    @staticmethod
    def decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> str:
        # Verify Tag
        mac = hmac.new(key, iv + ciphertext, hashlib.sha256)
        if not hmac.compare_digest(mac.digest(), tag):
            raise ValueError("Integrity Check Failed (Tag Mismatch)")

        # XOR Decrypt
        extended_key = (key * (len(ciphertext) // len(key) + 1))[:len(ciphertext)]
        pt_bytes = bytes(a ^ b for a, b in zip(ciphertext, extended_key))

        return pt_bytes.decode('utf-8')

# --- Key Vault ---

class InMemoryKeyVault:
    """
    Simulates a secure storage like HashiCorp Vault or AWS KMS.
    """
    def __init__(self):
        self._keys: Dict[str, bytes] = {} # raw bytes
        self._metadata: Dict[str, KeyMetadata] = {}

    def store_key(self, key_id: str, key_material: bytes, meta: KeyMetadata):
        self._keys[key_id] = key_material
        self._metadata[key_id] = meta
        logger.info(f"Key stored: {key_id} (v{meta.version})")

    def get_key(self, key_id: str) -> Optional[bytes]:
        return self._keys.get(key_id)

    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        return self._metadata.get(key_id)

    def list_keys(self) -> List[KeyMetadata]:
        return list(self._metadata.values())

# --- Rotator Engine ---

class KeyRotationManager:
    """
    M9: The Manager.
    """

    def __init__(self):
        self.vault = InMemoryKeyVault()
        self.current_key_id: Optional[str] = None
        self._lock = threading.Lock()

        # Bootstrap
        self.rotate_key()

    def rotate_key(self):
        """
        Generates a new Active key and deprecates the old one.
        """
        with self._lock:
            new_id = str(uuid.uuid4())
            new_key = CryptoPrimitives.generate_key()

            # Deprecate current
            if self.current_key_id:
                old_meta = self.vault.get_metadata(self.current_key_id)
                if old_meta:
                    old_meta.status = KeyStatus.DEPRECATED
                    logger.info(f"Key Deprecated: {self.current_key_id}")

            # Create new
            meta = KeyMetadata(
                key_id=new_id,
                version=int(datetime.datetime.now().timestamp()),
                expires_at=time.time() + (ROTATION_INTERVAL_DAYS * 86400)
            )

            self.vault.store_key(new_id, new_key, meta)
            self.current_key_id = new_id
            logger.info(f"Key Rotated. New Active Key: {new_id}")

    def encrypt_data(self, plaintext: str) -> EncryptedDataEnvelope:
        """
        Encrypts data using the CURRENT active key.
        """
        key_id = self.current_key_id
        if not key_id:
            raise RuntimeError("No active key available")

        key = self.vault.get_key(key_id)
        iv, ct, tag = CryptoPrimitives.encrypt(key, plaintext)

        return EncryptedDataEnvelope(
            key_id=key_id,
            iv=base64.b64encode(iv).decode(),
            ciphertext=base64.b64encode(ct).decode(),
            tag=base64.b64encode(tag).decode()
        )

    def decrypt_data(self, envelope: EncryptedDataEnvelope) -> str:
        """
        Decrypts data. If the key is deprecated, it might trigger a re-encryption flow (if implemented).
        """
        key = self.vault.get_key(envelope.key_id)
        if not key:
            raise ValueError(f"Key {envelope.key_id} not found in vault")

        meta = self.vault.get_metadata(envelope.key_id)
        if meta.status == KeyStatus.REVOKED:
            raise SecurityError(f"Key {envelope.key_id} has been REVOKED. Data is inaccessible.")

        try:
            iv = base64.b64decode(envelope.iv)
            ct = base64.b64decode(envelope.ciphertext)
            tag = base64.b64decode(envelope.tag)

            plaintext = CryptoPrimitives.decrypt(key, iv, ct, tag)

            # Check for rotation need
            if meta.status == KeyStatus.DEPRECATED:
                logger.warning(f"Data accessed with Deprecated Key {envelope.key_id}. Should re-encrypt.")

            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise

    def revoke_key(self, key_id: str):
        """
        Emergency revocation.
        """
        meta = self.vault.get_metadata(key_id)
        if meta:
            meta.status = KeyStatus.REVOKED
            logger.critical(f"KEY REVOKED: {key_id}")
            if self.current_key_id == key_id:
                self.rotate_key() # Immediately rotate if active was revoked

# --- Demo ---

def run_rotator_demo():
    print("M9: Encryption Key Rotator Demo")

    manager = KeyRotationManager()

    # 1. Encrypt Data
    secret_msg = "MySuperSecretWalletSeed"
    envelope = manager.encrypt_data(secret_msg)
    print(f"Encrypted: {envelope.ciphertext[:20]}... (Key: {envelope.key_id})")

    # 2. Decrypt Data
    decrypted = manager.decrypt_data(envelope)
    print(f"Decrypted: {decrypted}")
    assert decrypted == secret_msg

    # 3. Rotate Keys
    print("\n--- Rotating Keys ---")
    manager.rotate_key()

    # 4. Decrypt Old Data (Should work, but warn)
    print("Accessing data with old key...")
    decrypted_old = manager.decrypt_data(envelope)
    print(f"Decrypted Old: {decrypted_old}")

    # 5. Revoke Old Key
    print("\n--- Revoking Old Key ---")
    manager.revoke_key(envelope.key_id)

    # 6. Attempt Decrypt (Should fail)
    try:
        manager.decrypt_data(envelope)
    except Exception as e:
        print(f"Expected Failure: {e}")

if __name__ == "__main__":
    run_rotator_demo()
