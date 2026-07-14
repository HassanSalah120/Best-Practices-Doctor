from __future__ import annotations

import hashlib

from core.hashing import fast_hash_hex


def test_fast_hash_is_stable_standard_library_sha256() -> None:
    payload = "same code on every platform"
    assert fast_hash_hex(payload, 16) == hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    assert fast_hash_hex(payload, 0) == hashlib.sha256(payload.encode("utf-8")).hexdigest()
