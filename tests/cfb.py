from __future__ import annotations

import struct

SECTOR = 512
MINI = 64
CUTOFF = 4096
FREE, END, FATSECT = 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF


class _Node:
    def __init__(self, name: str, data: bytes | None = None) -> None:
        self.name = name
        self.data = data
        self.children: dict[str, _Node] = {}
        self.sid = 0
        self.start = END
        self.right = NOSTREAM
        self.child = NOSTREAM


def _key(name: str) -> tuple[int, str]:
    return len(name), name.upper()


def _sectors(n: int, size: int) -> int:
    return (n + size - 1) // size


def write_cfb(streams: dict[str, bytes]) -> bytes:
    root = _Node("Root Entry")
    for path, data in streams.items():
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            node = node.children.setdefault(part, _Node(part))
        node.children[parts[-1]] = _Node(parts[-1], data)

    order: list[_Node] = []

    def number(node: _Node) -> None:
        node.sid = len(order)
        order.append(node)
        for child in sorted(node.children.values(), key=lambda c: _key(c.name)):
            number(child)

    number(root)
    for node in order:
        kids = sorted(node.children.values(), key=lambda c: _key(c.name))
        if kids:
            node.child = kids[0].sid
            for a, b in zip(kids, kids[1:]):
                a.right = b.sid

    ministream = bytearray()
    minifat: list[int] = []
    big: list[_Node] = []
    for node in order:
        if node.data is None:
            continue
        if len(node.data) >= CUTOFF:
            big.append(node)
            continue
        if not node.data:
            continue
        n = _sectors(len(node.data), MINI)
        node.start = len(minifat)
        minifat.extend(range(node.start + 1, node.start + n))
        minifat.append(END)
        ministream += node.data.ljust(n * MINI, b"\0")

    dir_secs = _sectors(len(order) * 128, SECTOR)
    minifat_secs = _sectors(len(minifat) * 4, SECTOR)
    mini_secs = _sectors(len(ministream), SECTOR)
    big_secs = sum(_sectors(len(n.data), SECTOR) for n in big)
    fat_secs = 1
    while fat_secs * 128 < fat_secs + dir_secs + minifat_secs + mini_secs + big_secs:
        fat_secs += 1

    fat: list[int] = [FATSECT] * fat_secs
    body = bytearray()

    def alloc(data: bytes) -> int:
        n = _sectors(len(data), SECTOR)
        start = len(fat)
        fat.extend(range(start + 1, start + n))
        fat.append(END)
        body.extend(data.ljust(n * SECTOR, b"\0"))
        return start

    dir_start_placeholder = len(fat)
    fat.extend(range(dir_start_placeholder + 1, dir_start_placeholder + dir_secs))
    fat.append(END)
    dir_offset = len(body)
    body.extend(b"\0" * dir_secs * SECTOR)
    minifat_start = alloc(b"".join(struct.pack("<I", v) for v in minifat)) if minifat else END
    root.start = alloc(bytes(ministream)) if ministream else END
    for node in big:
        node.start = alloc(node.data)

    entries = bytearray()
    for node in order:
        name = node.name.encode("utf-16-le") + b"\0\0"
        kind = 5 if node is root else (2 if node.data is not None else 1)
        size = len(ministream) if node is root else len(node.data or b"")
        entries += name.ljust(64, b"\0") + struct.pack("<HBB", len(name), kind, 1)
        entries += struct.pack("<III", NOSTREAM, node.right, node.child)
        entries += b"\0" * 16 + struct.pack("<I", 0) + b"\0" * 16
        entries += struct.pack("<IQ", node.start, size)
    entries = entries.ljust(dir_secs * SECTOR, b"\0")
    for i in range(len(order), dir_secs * 4):
        struct.pack_into("<III", entries, i * 128 + 68, NOSTREAM, NOSTREAM, NOSTREAM)
    body[dir_offset : dir_offset + len(entries)] = entries

    fat_bytes = b"".join(struct.pack("<I", v) for v in fat).ljust(fat_secs * SECTOR, b"\xff")
    difat = list(range(fat_secs)) + [FREE] * (109 - fat_secs)
    header = (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 16
        + struct.pack("<HHHHH", 0x3E, 3, 0xFFFE, 9, 6) + b"\0" * 6
        + struct.pack("<IIIIIIIII", 0, fat_secs, fat_secs, 0, CUTOFF, minifat_start, minifat_secs, END, 0)
        + b"".join(struct.pack("<I", v) for v in difat)
    )
    return header + fat_bytes + bytes(body)
