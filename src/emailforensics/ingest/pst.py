from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from emailforensics.ingest.mapi import (
    ATTACH_EMBEDDED_MSG,
    FIXED_SIZE,
    PR_ATTACH_DATA,
    PR_ATTACH_METHOD,
    PR_MESSAGE_CLASS,
    PT_BINARY,
    MapiAttachment,
    MapiItem,
    NamedProp,
    Prop,
    Props,
    decode,
    item_codepage,
    parse_name_map,
)

PST_SIGNATURE = b"!BDN"
RECOVERABLE_ITEMS = "recoverable items"
_HN_BLOCK = 8176


def _hn_alloc(buf: bytes, hid: int) -> bytes | None:
    index, block = (hid >> 5) & 0x7FF, hid >> 16
    base = block * _HN_BLOCK
    if hid & 0x1F or index == 0 or base + 2 > len(buf):
        return None
    pagemap = base + struct.unpack_from("<H", buf, base)[0]
    if pagemap + 4 > len(buf) or index > struct.unpack_from("<H", buf, pagemap)[0]:
        return None
    start, end = struct.unpack_from("<HH", buf, pagemap + 4 + 2 * (index - 1))
    return buf[base + start : base + end]


def _bth_records(buf: bytes, hid: int, cb_key: int, cb_ent: int, levels: int) -> list[bytes]:
    node = _hn_alloc(buf, hid) if hid else None
    if node is None:
        return []
    if levels == 0:
        size = cb_key + cb_ent
        return [node[i : i + size] for i in range(0, len(node) - size + 1, size)]
    out = []
    size = cb_key + 4
    for i in range(0, len(node) - size + 1, size):
        child = struct.unpack_from("<I", node, i + cb_key)[0]
        out.extend(_bth_records(buf, child, cb_key, cb_ent, levels - 1))
    return out


def property_context(buf: bytes, names: dict[int, NamedProp]) -> tuple[Props, int]:
    if len(buf) < 8 or buf[2] != 0xEC or buf[3] != 0xBC:
        raise ValueError("embedded message is not a property context")
    bth = _hn_alloc(buf, struct.unpack_from("<I", buf, 4)[0])
    if bth is None or len(bth) < 8 or bth[0] != 0xB5:
        raise ValueError("embedded message has no property BTH")
    cb_key, cb_ent, levels = bth[1], bth[2], bth[3]
    props: Props = {}
    unreachable = 0
    for rec in _bth_records(buf, struct.unpack_from("<I", bth, 4)[0], cb_key, cb_ent, levels):
        pid = struct.unpack_from("<H", rec)[0]
        ptype, hnid = struct.unpack_from("<HI", rec, cb_key)
        size = FIXED_SIZE.get(ptype)
        if size is not None and size <= 4:
            data = rec[cb_key + 2 : cb_key + 2 + size]
        elif hnid == 0:
            data = b""
        else:
            data = _hn_alloc(buf, hnid)
            if data is None:
                unreachable += 1
                continue
        props[pid] = Prop(pid, ptype, data, names.get(pid))
    return props, unreachable


@dataclass
class PstEntry:
    item_path: str
    folder_path: list[str]
    state: str
    item: MapiItem | None = None
    error: str | None = None


@dataclass
class _Reader:
    names: dict[int, NamedProp]
    codepage: str
    seen: set[str] = field(default_factory=set)
    tick: Callable[[], None] = field(default=lambda: None)

    def props(self, record_set, skip: frozenset[int] = frozenset()) -> Props:
        out: Props = {}
        for e in record_set.entries:
            pid = e.entry_type
            if pid in skip:
                continue
            out[pid] = Prop(pid, e.value_type, e.data, self.names.get(pid))
        return out

    def item_props(self, item, skip: frozenset[int] = frozenset()) -> Props:
        return self.props(item.get_record_set(0), skip) if item.number_of_record_sets else {}

    def recipients(self, message) -> list[Props]:
        r = message.recipients
        if r is None:
            return []
        return [self.props(rs) for rs in r.record_sets]

    def read(self, att) -> bytes:
        size = att.size or 0
        if not size:
            return b""
        att.seek_offset(0)
        return att.read_buffer(size)

    def embedded(self, att) -> MapiItem:
        props, unreachable = property_context(self.read(att), self.names)
        defects = ["embedded message: recipients and attachments are not reachable through libpff"]
        if unreachable:
            defects.append(f"embedded message: {unreachable} properties stored in sub-nodes were not read")
        return MapiItem(props=props, codepage=item_codepage(props, self.codepage), defects=defects)

    def attachment(self, att) -> MapiAttachment:
        props = self.item_props(att, frozenset({PR_ATTACH_DATA}))
        if decode(props.get(PR_ATTACH_METHOD)) == ATTACH_EMBEDDED_MSG:
            return MapiAttachment(props, self.embedded(att))
        props[PR_ATTACH_DATA] = Prop(PR_ATTACH_DATA, PT_BINARY, self.read(att))
        return MapiAttachment(props)

    def message(self, message) -> MapiItem:
        props = self.item_props(message)
        attachments = []
        if getattr(message, "number_of_attachments", 0):
            attachments = [self.attachment(a) for a in message.attachments]
        return MapiItem(
            props=props,
            recipients=self.recipients(message) if hasattr(message, "recipients") else [],
            attachments=attachments,
            codepage=item_codepage(props, self.codepage),
        )

    def path(self, base: str) -> str:
        path, n = base, 1
        while path in self.seen:
            n += 1
            path = f"{base}#{n}"
        self.seen.add(path)
        return path

    def entry(self, base: str, folder_path: list[str], state: str, message) -> PstEntry:
        path = self.path(base)
        try:
            return PstEntry(path, folder_path, state, self.message(message))
        except Exception as e:
            return PstEntry(path, folder_path, state, error=f"{type(e).__name__}: {e}")


def _name_map(pst) -> dict[int, NamedProp]:
    try:
        item = pst.get_name_to_id_map()
    except OSError:
        return {}
    if item is None or not item.number_of_record_sets:
        return {}
    streams = {e.entry_type: e.data or b"" for e in item.get_record_set(0).entries if e.entry_type in (2, 3, 4)}
    return parse_name_map(streams.get(2, b""), streams.get(3, b""), streams.get(4, b""))


def _walk(reader: _Reader, folder, path: list[str], recoverable: bool) -> Iterator[PstEntry]:
    state = "recoverable" if recoverable else "live"
    for i in range(folder.number_of_sub_messages):
        try:
            message = folder.get_sub_message(i)
        except OSError as e:
            reader.tick()
            yield PstEntry(reader.path(f"pst:{folder.identifier}:{i}"), path, state, error=f"OSError: {e}")
            continue
        entry = reader.entry(f"pst:{message.identifier}", path, state, message)
        reader.tick()
        yield entry
    for j in range(folder.number_of_sub_folders):
        try:
            sub = folder.get_sub_folder(j)
        except OSError as e:
            yield PstEntry(reader.path(f"pst:folder:{folder.identifier}:{j}"), path, state, error=f"OSError: {e}")
            continue
        name = sub.name or ""
        yield from _walk(reader, sub, path + [name], recoverable or name.lower() == RECOVERABLE_ITEMS)


def _orphans(reader: _Reader, pst) -> Iterator[PstEntry]:
    for i in range(pst.number_of_orphan_items):
        try:
            item = pst.get_orphan_item(i)
            if not item.number_of_record_sets or item.get_record_set(0).get_entry_by_type(PR_MESSAGE_CLASS) is None:
                reader.tick()
                continue
        except OSError:
            reader.tick()
            continue
        entry = reader.entry(f"pst:orphan:{item.identifier}", [], "orphan", item)
        reader.tick()
        yield entry


def count_units(folder, pst=None) -> int:
    n = folder.number_of_sub_messages
    for j in range(folder.number_of_sub_folders):
        try:
            n += count_units(folder.get_sub_folder(j))
        except OSError:
            continue
    if pst is not None:
        n += pst.number_of_orphan_items
    return n


def read_pst(
    path: Path,
    on_total: Callable[[int], None] | None = None,
    tick: Callable[[], None] | None = None,
) -> Iterator[PstEntry]:
    import pypff

    with open(path, "rb") as fh:
        pst = pypff.file()
        pst.open_file_object(fh)
        try:
            codepage = (pst.ascii_codepage or b"cp1252").decode("ascii", "replace")
            reader = _Reader(_name_map(pst), codepage)
            if tick is not None:
                reader.tick = tick
            root = pst.get_root_folder()
            if on_total is not None:
                on_total(count_units(root, pst))
            yield from _walk(reader, root, [], False)
            yield from _orphans(reader, pst)
        finally:
            pst.close()
