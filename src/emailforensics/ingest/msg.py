from __future__ import annotations

import struct
from pathlib import Path

import olefile

from emailforensics.ingest.mapi import (
    FIXED_SIZE,
    MV_FLAG,
    PT_BINARY,
    PT_CLSID,
    PT_OBJECT,
    VARIABLE,
    MapiAttachment,
    MapiItem,
    NamedProp,
    Prop,
    Props,
    item_codepage,
    pack_multi,
    parse_name_map,
)

CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
PROPERTIES = "__properties_version1.0"
NAMEID = "__nameid_version1.0"
RECIP_PREFIX = "__recip_version1.0_#"
ATTACH_PREFIX = "__attach_version1.0_#"
EMBEDDED = "__substg1.0_3701000D"
TOP_HEADER, EMBEDDED_HEADER, SUB_HEADER = 32, 24, 8


class _Reader:
    def __init__(self, ole: olefile.OleFileIO, default_codepage: str) -> None:
        self.ole = ole
        self.default_codepage = default_codepage
        self.entries = [tuple(e) for e in ole.listdir(streams=True, storages=True)]
        self.names = self._names()

    def stream(self, path: list[str]) -> bytes | None:
        return self.ole.openstream(path).read() if self.ole.exists("/".join(path)) else None

    def _names(self) -> dict[int, NamedProp]:
        def part(n: str) -> bytes:
            return self.stream([NAMEID, f"__substg1.0_{n}"]) or b""

        return parse_name_map(part("00020102"), part("00030102"), part("00040102"))

    def children(self, prefix: list[str], start: str) -> list[list[str]]:
        n = len(prefix)
        found = {
            e[n] for e in self.entries if len(e) > n and list(e[:n]) == prefix and e[n].startswith(start)
        }
        return [prefix + [name] for name in sorted(found)]

    def value(self, prefix: list[str], tag: int, ptype: int, inline: bytes) -> bytes | None:
        name = f"__substg1.0_{tag:08X}"
        if ptype & MV_FLAG:
            base = ptype & ~MV_FLAG
            data = self.stream(prefix + [name])
            if base not in VARIABLE or data is None:
                return data
            step = 8 if base == PT_BINARY else 4
            count = len(data) // step
            return pack_multi([self.stream(prefix + [f"{name}-{i:08X}"]) or b"" for i in range(count)])
        if ptype in VARIABLE or ptype == PT_CLSID:
            data = self.stream(prefix + [name])
            return data if data is not None or ptype != PT_CLSID else inline[:16]
        return inline[: FIXED_SIZE.get(ptype, 8)]

    def props(self, prefix: list[str], header: int) -> Props:
        data = self.stream(prefix + [PROPERTIES]) or b""
        out: Props = {}
        for off in range(header, len(data) - 15, 16):
            tag = struct.unpack_from("<I", data, off)[0]
            ptype, pid = tag & 0xFFFF, tag >> 16
            if ptype == PT_OBJECT:
                continue
            out[pid] = Prop(pid, ptype, self.value(prefix, tag, ptype, data[off + 8 : off + 16]), self.names.get(pid))
        return out

    def item(self, prefix: list[str], header: int) -> MapiItem:
        props = self.props(prefix, header)
        attachments = []
        for a in self.children(prefix, ATTACH_PREFIX):
            embedded = a + [EMBEDDED]
            inner = self.item(embedded, EMBEDDED_HEADER) if tuple(embedded) in self.entries else None
            attachments.append(MapiAttachment(self.props(a, SUB_HEADER), inner))
        return MapiItem(
            props=props,
            recipients=[self.props(r, SUB_HEADER) for r in self.children(prefix, RECIP_PREFIX)],
            attachments=attachments,
            codepage=item_codepage(props, self.default_codepage),
        )


def read_msg(path: Path, default_codepage: str = "cp1252") -> MapiItem:
    with olefile.OleFileIO(str(path)) as ole:
        return _Reader(ole, default_codepage).item([], TOP_HEADER)
