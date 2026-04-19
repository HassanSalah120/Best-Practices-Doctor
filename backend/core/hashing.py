"""
Hashing helpers with optional xxhash acceleration.
"""

from __future__ import annotations

import hashlib
from typing import Union

try:
    import xxhash  # type: ignore

    _HAS_XXHASH = True
except Exception:
    xxhash = None
    _HAS_XXHASH = False


BytesLike = Union[str, bytes, bytearray, memoryview]


def _to_bytes(data: BytesLike) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    if isinstance(data, memoryview):
        return data.tobytes()
    return str(data).encode("utf-8", errors="ignore")


def fast_hash_hex(data: BytesLike, length: int = 16) -> str:
    """
    Fast deterministic hash.

    Uses xxhash when available, falls back to sha256.
    """
    raw = _to_bytes(data)
    if _HAS_XXHASH and xxhash is not None:
        digest = xxhash.xxh3_128_hexdigest(raw)
    else:
        digest = hashlib.sha256(raw).hexdigest()
    if length <= 0:
        return digest
    return digest[:length]
