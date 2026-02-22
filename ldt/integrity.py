"""
Integrity helpers — BLAKE3 hashing.

hash_bytes(data) → bytes[32]   (raw digest)
"""

from __future__ import annotations

import blake3 as _b3


def hash_bytes(data: bytes) -> bytes:
    """Return the 32-byte BLAKE3 digest of *data*."""
    return _b3.blake3(data).digest()


def verify(data: bytes, expected: bytes) -> bool:
    """Return True if BLAKE3(data) == expected digest."""
    return hash_bytes(data) == expected
