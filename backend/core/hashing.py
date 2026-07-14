"""Deterministic hashing helpers used by caches and persisted identities."""

from __future__ import annotations

import hashlib
from typing import Union


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
    Return a deterministic hash regardless of optional installed packages.

    This value is used in finding fingerprints, cache keys, project history,
    and report snapshots.  Selecting an algorithm based on whether xxhash was
    installed made identical scans produce different identities across
    Windows, Linux, packaged apps, and development environments.
    """
    raw = _to_bytes(data)
    digest = hashlib.sha256(raw).hexdigest()
    if length <= 0:
        return digest
    return digest[:length]
