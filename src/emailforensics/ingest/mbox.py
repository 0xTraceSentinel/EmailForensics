from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

_FROM_LINE = re.compile(rb"^From [^\r\n]*(?:\r?\n|\Z)", re.M)
_ESCAPED_FROM = re.compile(rb"^>(>*From )", re.M)


@dataclass(frozen=True)
class MboxEntry:
    index: int
    offset: int
    envelope: str
    raw: bytes


def _is_separator(data, start: int) -> bool:
    return (
        start == 0
        or data[start - 2 : start] == b"\n\n"
        or data[start - 4 : start] == b"\r\n\r\n"
    )


def split_mbox(data) -> Iterator[MboxEntry]:
    if data[:5] != b"From ":
        raise ValueError("not an mbox file: does not start with a From_ line")
    seps = [m for m in _FROM_LINE.finditer(data) if _is_separator(data, m.start())]
    for i, m in enumerate(seps):
        end = seps[i + 1].start() if i + 1 < len(seps) else len(data)
        raw = bytes(data[m.end() : end])
        if raw.endswith(b"\r\n\r\n"):
            raw = raw[:-2]
        elif raw.endswith(b"\n\n"):
            raw = raw[:-1]
        envelope = m.group().rstrip(b"\r\n")[5:].decode("latin-1")
        yield MboxEntry(index=i, offset=m.end(), envelope=envelope, raw=raw)


def unescape(raw: bytes) -> bytes:
    return _ESCAPED_FROM.sub(rb"\1", raw)
