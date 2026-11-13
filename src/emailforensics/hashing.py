from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

_CHUNK = 1 << 20


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, on_bytes: Callable[[int], None] | None = None) -> str:
    h = hashlib.sha256()
    done = 0
    with open(path, "rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
            if on_bytes is not None:
                done += len(chunk)
                on_bytes(done)
    return h.hexdigest()
