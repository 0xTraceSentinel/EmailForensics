import struct
import uuid
from datetime import datetime, timezone

from cfb import write_cfb

from emailforensics.ingest.mapi import to_parsed
from emailforensics.ingest.msg import read_msg

PSETID_COMMON = uuid.UUID("00062008-0000-0000-c000-000000000046")
SUBMIT = datetime(2023, 6, 13, 6, 30, tzinfo=timezone.utc)


def u(s: str) -> bytes:
    return s.encode("utf-16-le") + b"\0\0"


def ft(dt: datetime) -> bytes:
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return struct.pack("<Q", (delta.days * 86400 + delta.seconds) * 10_000_000)


def storage(prefix: str, header: bytes, props: list[tuple[int, int, bytes]]) -> dict[str, bytes]:
    streams = {}
    table = bytearray(header)
    for pid, ptype, value in props:
        tag = (pid << 16) | ptype
        if ptype in (0x001F, 0x001E, 0x0102):
            streams[f"{prefix}__substg1.0_{tag:08X}"] = value
            table += struct.pack("<III", tag, 6, len(value)) + b"\0" * 4
        elif ptype == 0x101F:
            lengths = b"".join(struct.pack("<I", len(v)) for v in value)
            streams[f"{prefix}__substg1.0_{tag:08X}"] = lengths
            for i, v in enumerate(value):
                streams[f"{prefix}__substg1.0_{tag:08X}-{i:08X}"] = v
            table += struct.pack("<III", tag, 6, len(lengths)) + b"\0" * 4
        elif ptype == 0x000D:
            table += struct.pack("<III", tag, 6, 0xFFFFFFFF) + b"\0" * 4
        else:
            table += struct.pack("<II", tag, 6) + value.ljust(8, b"\0")
    streams[f"{prefix}__properties_version1.0"] = bytes(table)
    return streams


def build_msg(path):
    streams = {}
    streams.update(storage("", b"\0" * 8 + struct.pack("<IIII", 1, 2, 1, 2) + b"\0" * 8, [
        (0x001A, 0x001F, u("IPM.Note")),
        (0x0037, 0x001F, u("Project Falcon – go ahead")),
        (0x0039, 0x0040, ft(SUBMIT)),
        (0x0042, 0x001F, u("Jane CFO")),
        (0x0065, 0x001F, u("cfo@group.example")),
        (0x1000, 0x001F, u("We're going ahead, tell the bank. " * 200)),
        (0x1039, 0x001F, u("<a@group.example> <b@group.example>")),
        (0x3FF1, 0x101F, [u("en-ZA"), u("af-ZA")]),
        (0x8000, 0x001F, u("Falcon")),
    ]))
    streams.update(storage("__recip_version1.0_#00000000/", b"\0" * 8, [
        (0x0C15, 0x0003, struct.pack("<i", 2)),
        (0x3001, 0x001F, u("Legal")),
        (0x3003, 0x001F, u("legal@group.example")),
    ]))
    streams.update(storage("__attach_version1.0_#00000000/", b"\0" * 8, [
        (0x3705, 0x0003, struct.pack("<i", 1)),
        (0x3707, 0x001F, u("minutes.pdf")),
        (0x3701, 0x0102, b"%PDF-1.7 minutes"),
    ]))
    streams.update(storage("__attach_version1.0_#00000001/", b"\0" * 8, [
        (0x3705, 0x0003, struct.pack("<i", 5)),
        (0x3701, 0x000D, b""),
    ]))
    streams.update(storage("__attach_version1.0_#00000001/__substg1.0_3701000D/", b"\0" * 24, [
        (0x001A, 0x001F, u("IPM.Note")),
        (0x0037, 0x001F, u("Term sheet")),
    ]))
    streams["__nameid_version1.0/__substg1.0_00020102"] = PSETID_COMMON.bytes_le
    streams["__nameid_version1.0/__substg1.0_00030102"] = struct.pack("<IHH", 0x8539, 3 << 1, 0)
    streams["__nameid_version1.0/__substg1.0_00040102"] = b""
    path.write_bytes(write_cfb(streams))
    return path


def test_msg_round_trip(tmp_path):
    item = read_msg(build_msg(tmp_path / "falcon.msg"))
    m = to_parsed(item)

    assert m.subject == "Project Falcon – go ahead"
    assert m.date_utc == SUBMIT
    assert m.from_addr == [{"name": "Jane CFO", "address": "cfo@group.example"}]
    assert m.cc_addrs == [{"name": "Legal", "address": "legal@group.example"}]
    assert m.references == ["<a@group.example>", "<b@group.example>"]
    assert m.body_text.startswith("We're going ahead") and len(m.body_text) > 4096
    assert m.mapi.props["0x3ff1101f"]["value"] == ["en-ZA", "af-ZA"]
    assert m.mapi.props["{00062008-0000-0000-c000-000000000046}:0x8539:0x001f"]["value"] == "Falcon"

    pdf, embedded = m.attachments
    assert (pdf.filename, pdf.data) == ("minutes.pdf", b"%PDF-1.7 minutes")
    assert embedded.content_type == "application/vnd.ms-outlook"
    [(path, child)] = m.children
    assert (path, child.subject) == ("2", "Term sheet")


def test_msg_hash_is_stable(tmp_path):
    a = to_parsed(read_msg(build_msg(tmp_path / "a.msg")))
    b = to_parsed(read_msg(build_msg(tmp_path / "b.msg")))
    assert a.sha256 == b.sha256
