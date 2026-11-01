import struct
from dataclasses import dataclass, field

import pytest

from emailforensics.ingest.mapi import NamedProp, decode, to_parsed
from emailforensics.ingest.pst import _orphans, _Reader, _walk, property_context


def u(s: str) -> bytes:
    return s.encode("utf-16-le")


def heap(records: list[tuple[int, int, bytes]]) -> bytes:
    allocs: list[bytes] = [b"", b""]
    rows = []
    for pid, ptype, value in sorted(records):
        if ptype in (0x0003, 0x000B):
            rows.append(struct.pack("<HH", pid, ptype) + value.ljust(4, b"\0"))
        else:
            allocs.append(value)
            rows.append(struct.pack("<HHI", pid, ptype, len(allocs) << 5))
    rows.append(struct.pack("<HHI", 0x1000, 0x001F, 0x00000041))
    allocs[1] = b"".join(rows)
    allocs[0] = struct.pack("<BBBBI", 0xB5, 2, 6, 0, 2 << 5)

    body = bytearray(b"\0" * 12)
    offsets = []
    for a in allocs:
        offsets.append(len(body))
        body += a
    offsets.append(len(body))
    pagemap = len(body)
    body += struct.pack("<HH", len(allocs), 0) + b"".join(struct.pack("<H", o) for o in offsets)
    struct.pack_into("<HBBI", body, 0, pagemap, 0xEC, 0xBC, 1 << 5)
    return bytes(body)


def test_property_context_reads_inline_and_heap_values():
    buf = heap([
        (0x0037, 0x001F, u("Term sheet")),
        (0x0E07, 0x0003, struct.pack("<i", 1)),
        (0x8001, 0x000B, b"\x01"),
        (0x3007, 0x0040, struct.pack("<Q", 133309206000000000)),
    ])
    names = {0x8001: NamedProp("00062008-0000-0000-c000-000000000046", 0x8503, None)}
    props, unreachable = property_context(buf, names)
    assert unreachable == 1
    assert decode(props[0x0037]) == "Term sheet"
    assert decode(props[0x0E07]) == 1
    assert decode(props[0x8001]) is True and props[0x8001].named == names[0x8001]
    assert decode(props[0x3007]).year == 2023


def test_property_context_rejects_other_heaps():
    with pytest.raises(ValueError):
        property_context(b"\x0c\x00\xec\x7c" + b"\0" * 20, {})


@dataclass
class Entry:
    entry_type: int
    value_type: int
    data: bytes | None


@dataclass
class RecordSet:
    entries: list[Entry]

    def get_entry_by_type(self, t):
        return next((e for e in self.entries if e.entry_type == t), None)


@dataclass
class Item:
    identifier: int
    subject: str
    recipients: object = None
    number_of_attachments: int = 0
    attachments: list = field(default_factory=list)

    @property
    def number_of_record_sets(self):
        return 1

    def get_record_set(self, i):
        return RecordSet([Entry(0x001A, 0x001F, u("IPM.Note")), Entry(0x0037, 0x001F, u(self.subject))])


@dataclass
class Folder:
    name: str | None
    identifier: int
    messages: list = field(default_factory=list)
    folders: list = field(default_factory=list)

    @property
    def number_of_sub_messages(self):
        return len(self.messages)

    def get_sub_message(self, i):
        m = self.messages[i]
        if isinstance(m, Exception):
            raise m
        return m

    @property
    def number_of_sub_folders(self):
        return len(self.folders)

    def get_sub_folder(self, i):
        return self.folders[i]


def test_walk_records_folder_paths_and_recoverable_items():
    root = Folder(None, 290, folders=[
        Folder("Top of Information Store", 8354, folders=[
            Folder("Inbox", 8578, [Item(2097284, "Board pack"), Item(2097284, "Duplicate id")]),
        ]),
        Folder("Recoverable Items", 8400, folders=[
            Folder("Purges", 8432, [Item(2097400, "Deleted minutes draft"), OSError("bad block")]),
        ]),
    ])
    entries = list(_walk(_Reader({}, "cp1252"), root, [], False))

    assert [(e.item_path, e.folder_path, e.state) for e in entries] == [
        ("pst:2097284", ["Top of Information Store", "Inbox"], "live"),
        ("pst:2097284#2", ["Top of Information Store", "Inbox"], "live"),
        ("pst:2097400", ["Recoverable Items", "Purges"], "recoverable"),
        ("pst:8432:1", ["Recoverable Items", "Purges"], "recoverable"),
    ]
    assert to_parsed(entries[2].item).subject == "Deleted minutes draft"
    assert entries[3].error == "OSError: bad block"


def test_orphans_keep_only_message_items():
    class Pst:
        items = [Item(3000, "Orphaned reply")]
        number_of_orphan_items = 1

        def get_orphan_item(self, i):
            return self.items[i]

    [entry] = list(_orphans(_Reader({}, "cp1252"), Pst()))
    assert (entry.item_path, entry.folder_path, entry.state) == ("pst:orphan:3000", [], "orphan")
