"""
Nexus Automation Framework - Cryptographic Utilities

Military-grade cryptographic operations for:
- Kill switch token generation/verification
- Audit chain integrity (hash chaining)
- Credential encryption/decryption
- Secure random generation
- HMAC-based message authentication
"""

import hashlib
import hmac
import os
import base64
import secrets
import json
import time
from typing import Optional, Tuple, Dict, Any
from datetime import datetime

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


# ══════════════════════════════════════════════════════════════════════════════
# SECURE RANDOM
# ══════════════════════════════════════════════════════════════════════════════

def generate_token(length: int = 64) -> str:
    """Generate a cryptographically secure token."""
    return secrets.token_urlsafe(length)


def generate_id(prefix: str = "") -> str:
    """Generate a unique identifier with optional prefix."""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    random_part = secrets.token_hex(4)
    if prefix:
        return f"{prefix}_{timestamp}_{random_part}"
    return f"{timestamp}_{random_part}"


def generate_nonce(size: int = 16) -> bytes:
    """Generate a cryptographic nonce."""
    return os.urandom(size)


# ══════════════════════════════════════════════════════════════════════════════
# HASHING
# ══════════════════════════════════════════════════════════════════════════════

def hash_sha256(data: str) -> str:
    """SHA-256 hash of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def hash_sha512(data: str) -> str:
    """SHA-512 hash of a string."""
    return hashlib.sha512(data.encode("utf-8")).hexdigest()


def hash_blake2b(data: str, digest_size: int = 32) -> str:
    """BLAKE2b hash (faster than SHA-256)."""
    return hashlib.blake2b(data.encode("utf-8"), digest_size=digest_size).hexdigest()


def hash_file(filepath: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """Hash a file using the specified algorithm."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
# HMAC AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════

def hmac_sign(message: str, secret: str, algorithm: str = "sha256") -> str:
    """Create HMAC signature for a message."""
    return hmac.new(
        secret.encode("utf-8"),
        message.encode("utf-8"),
        getattr(hashlib, algorithm)
    ).hexdigest()


def hmac_verify(message: str, signature: str, secret: str, algorithm: str = "sha256") -> bool:
    """Verify HMAC signature (constant-time comparison)."""
    expected = hmac_sign(message, secret, algorithm)
    return hmac.compare_digest(expected, signature)


# ══════════════════════════════════════════════════════════════════════════════
# AUDIT CHAIN
# ══════════════════════════════════════════════════════════════════════════════

class AuditChain:
    """
    Tamper-evident audit chain using hash linking.
    Each entry's hash includes the previous entry's hash,
    creating an immutable chain of events.
    """

    def __init__(self, secret: str = ""):
        self.secret = secret or generate_token(32)
        self._prev_hash = "GENESIS"

    def create_entry(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new chain entry with integrity hash."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "data": event_data,
            "prev_hash": self._prev_hash,
            "nonce": secrets.token_hex(8),
        }

        # Create hash of entry contents
        hash_input = json.dumps(entry, sort_keys=True, default=str)
        entry["hash"] = hmac_sign(hash_input, self.secret)

        self._prev_hash = entry["hash"]
        return entry

    def verify_chain(self, entries: list) -> Tuple[bool, int]:
        """
        Verify integrity of a chain of entries.
        Returns (is_valid, num_checked).
        """
        if not entries:
            return True, 0

        prev_hash = "GENESIS"
        for i, entry in enumerate(entries):
            # Verify previous hash linkage
            if entry.get("prev_hash") != prev_hash:
                return False, i

            # Verify entry hash
            entry_copy = {
                "timestamp": entry["timestamp"],
                "data": entry["data"],
                "prev_hash": entry["prev_hash"],
                "nonce": entry.get("nonce", ""),
            }
            hash_input = json.dumps(entry_copy, sort_keys=True, default=str)
            expected_hash = hmac_sign(hash_input, self.secret)

            if not hmac.compare_digest(entry.get("hash", ""), expected_hash):
                return False, i

            prev_hash = entry["hash"]

        return True, len(entries)


# ══════════════════════════════════════════════════════════════════════════════
# ENCRYPTION (requires `cryptography` package)
# ══════════════════════════════════════════════════════════════════════════════

class SecureVault:
    """
    Encrypt/decrypt sensitive data using Fernet (AES-128-CBC + HMAC).
    Falls back to base64 obfuscation if cryptography is not available.
    """

    def __init__(self, master_password: str = ""):
        self._master = master_password or generate_token(32)
        self._fernet = None

        if HAS_CRYPTOGRAPHY:
            salt = hashlib.sha256(self._master.encode()).digest()[:16]
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self._master.encode("utf-8")))
            self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a string."""
        if self._fernet:
            return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
        # Fallback: base64 + XOR obfuscation (not secure, but better than plaintext)
        return self._obfuscate(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a string."""
        if self._fernet:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        return self._deobfuscate(ciphertext)

    def _obfuscate(self, text: str) -> str:
        """Simple XOR obfuscation fallback."""
        key = self._master.encode("utf-8")
        result = bytes(
            b ^ key[i % len(key)]
            for i, b in enumerate(text.encode("utf-8"))
        )
        return base64.urlsafe_b64encode(result).decode("utf-8")

    def _deobfuscate(self, text: str) -> str:
        """Reverse XOR obfuscation."""
        key = self._master.encode("utf-8")
        data = base64.urlsafe_b64decode(text.encode("utf-8"))
        result = bytes(
            b ^ key[i % len(key)]
            for i, b in enumerate(data)
        )
        return result.decode("utf-8")


# ══════════════════════════════════════════════════════════════════════════════
# KILL SWITCH TOKEN
# ══════════════════════════════════════════════════════════════════════════════

class KillSwitchAuth:
    """
    Kill switch authentication using time-based tokens.
    Generates tokens that are valid for a configurable window.
    """

    def __init__(self, secret: str, window_seconds: int = 300):
        self.secret = secret
        self.window = window_seconds

    def generate_token(self) -> str:
        """Generate a time-based kill switch override token."""
        timestamp = int(time.time())
        window_key = timestamp // self.window
        message = f"kill_switch_override:{window_key}"
        return hmac_sign(message, self.secret)

    def verify_token(self, token: str) -> bool:
        """Verify a kill switch override token (checks current + previous window)."""
        timestamp = int(time.time())

        # Check current window
        window_key = timestamp // self.window
        message = f"kill_switch_override:{window_key}"
        if hmac.compare_digest(token, hmac_sign(message, self.secret)):
            return True

        # Check previous window (grace period)
        prev_key = window_key - 1
        message = f"kill_switch_override:{prev_key}"
        if hmac.compare_digest(token, hmac_sign(message, self.secret)):
            return True

        return False


# ══════════════════════════════════════════════════════════════════════════════
# CREDENTIAL STORE
# ══════════════════════════════════════════════════════════════════════════════

class CredentialStore:
    """
    Secure in-memory credential store with encryption at rest.
    Credentials are never logged or stored in plaintext.
    """

    def __init__(self, vault: Optional[SecureVault] = None):
        self._vault = vault or SecureVault()
        self._store: Dict[str, str] = {}

    def store(self, key: str, value: str):
        """Store an encrypted credential."""
        self._store[key] = self._vault.encrypt(value)

    def retrieve(self, key: str) -> Optional[str]:
        """Retrieve a decrypted credential."""
        encrypted = self._store.get(key)
        if encrypted is None:
            return None
        return self._vault.decrypt(encrypted)

    def delete(self, key: str):
        """Delete a credential."""
        self._store.pop(key, None)

    def has(self, key: str) -> bool:
        """Check if a credential exists."""
        return key in self._store

    def clear(self):
        """Securely clear all credentials."""
        self._store.clear()

    def list_keys(self) -> list:
        """List all credential keys (not values)."""
        return list(self._store.keys())


# ══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCES
# ══════════════════════════════════════════════════════════════════════════════

audit_chain = AuditChain()
secure_vault = SecureVault()
credential_store = CredentialStore(secure_vault)
