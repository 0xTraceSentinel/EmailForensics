import hashlib
import json
import struct
import uuid
from datetime import datetime, timezone

from emailforensics.ingest.mapi import (
    PS_PUBLIC_STRINGS,
    MapiAttachment,
    MapiItem,
    NamedProp,
    Prop,
    canonical_bytes,
    canonical_sha256,
    decode,
    pack_multi,
    parse_name_map,
    to_parsed,
)

PSETID_APPOINTMENT = "00062002-0000-0000-c000-000000000046"
SUBMIT = datetime(2023, 6, 13, 6, 30, tzinfo=timezone.utc)


def u(s: str) -> bytes:
    return s.encode("utf-16-le")


def ft(dt: datetime) -> bytes:
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    return struct.pack("<Q", (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10)


def props(*items) -> dict:
    return {p.id: p for p in items}


def note(*extra: Prop) -> MapiItem:
    base = props(
        Prop(0x001A, 0x001F, u("IPM.Note")),
        Prop(0x0037, 0x001F, u("\x01\x05RE: Project Falcon")),
        Prop(0x0039, 0x0040, ft(SUBMIT)),
        Prop(0x3007, 0x0040, ft(datetime(2023, 6, 12, 18, 0, tzinfo=timezone.utc))),
        Prop(0x0042, 0x001F, u("Jane CFO")),
        Prop(0x5D02, 0x001F, u("cfo@group.example")),
        Prop(0x0C1A, 0x001F, u("Assistant")),
        Prop(0x5D01, 0x001F, u("pa@group.example")),
        Prop(0x1000, 0x001F, u("We have decided. The board just needs to sign off.")),
        Prop(0x1035, 0x001F, u("<falcon-002@group.example>")),
        Prop(0x3FFA, 0x001F, u("Jane CFO")),
        Prop(0x0071, 0x0102, bytes(range(22))),
    )
    base.update(props(*extra))
    recipients = [
        props(Prop(0x0C15, 0x0003, struct.pack("<i", 1)), Prop(0x3001, 0x001F, u("Director One")),
              Prop(0x3003, 0x001F, u("/O=GROUP/CN=DIR1")), Prop(0x3002, 0x001F, u("EX")),
              Prop(0x39FE, 0x001F, u("director1@offshore.example"))),
        props(Prop(0x0C15, 0x0003, struct.pack("<i", 3)), Prop(0x3001, 0x001F, u("Hidden")),
              Prop(0x3003, 0x001F, u("hidden@group.example")), Prop(0x3002, 0x001F, u("SMTP"))),
    ]
    return MapiItem(props=base, recipients=recipients)


def test_sent_item_without_headers_falls_back_to_mapi():
    m = to_parsed(note())
    assert m.subject == "RE: Project Falcon"
    assert m.date_utc == SUBMIT and m.date_offset_minutes is None and m.date_raw is None
    assert any("PR_CLIENT_SUBMIT_TIME" in d for d in m.defects)
    assert m.from_addr == [{"name": "Jane CFO", "address": "cfo@group.example"}]
    assert m.sender_addr == [{"name": "Assistant", "address": "pa@group.example"}]
    assert m.to_addrs == [{"name": "Director One", "address": "director1@offshore.example"}]
    assert m.bcc_addrs == [{"name": "Hidden", "address": "hidden@group.example"}]
    assert m.rfc_message_id == "<falcon-002@group.example>"
    assert m.mapi.message_class == "IPM.Note"
    assert m.mapi.last_modifier_name == "Jane CFO"
    assert m.mapi.creation_time == datetime(2023, 6, 12, 18, 0, tzinfo=timezone.utc)
    assert m.mapi.conversation_index == bytes(range(22))
    assert m.mapi.recipients[0] == {
        "type": "to", "name": "Director One", "address": "/O=GROUP/CN=DIR1", "addrtype": "EX",
        "smtp": "director1@offshore.example",
    }
    assert m.mapi.props["0x00390040"] == {"name": "PR_CLIENT_SUBMIT_TIME", "value": SUBMIT.isoformat()}
    assert "0x1000001f" not in m.mapi.props


def test_transport_headers_win_and_keep_offset():
    headers = (
        "Received: from mx.group.example\r\n"
        "Date: Tue, 13 Jun 2023 08:30:00 +0200\r\n"
        "From: Jane CFO <cfo@group.example>\r\n"
        "To: director1@offshore.example\r\n"
        "Message-ID: <falcon-002@group.example>\r\n"
        "In-Reply-To: <falcon-001@group.example>\r\n"
        "Content-Type: multipart/mixed; boundary=\"b1\"\r\n"
    )
    m = to_parsed(note(Prop(0x007D, 0x001F, u(headers))))
    assert m.date_utc == SUBMIT and m.date_offset_minutes == 120
    assert m.headers[0] == ("Received", "from mx.group.example")
    assert m.in_reply_to == "<falcon-001@group.example>"
    assert m.to_addrs == [{"name": None, "address": "director1@offshore.example"}]
    assert m.bcc_addrs == [{"name": "Hidden", "address": "hidden@group.example"}]
    assert m.defects == []
    assert "0x007d001f" not in m.mapi.props


def test_hash_is_order_independent_and_content_sensitive():
    a = note()
    b = note()
    b.props = dict(reversed(list(b.props.items())))
    assert to_parsed(a).sha256 == to_parsed(b).sha256
    c = note(Prop(0x1000, 0x001F, u("Changed.")))
    assert to_parsed(c).sha256 != to_parsed(a).sha256
    assert to_parsed(a).sha256 == to_parsed(a).sha256


def test_named_properties_are_keyed_by_guid_not_local_id():
    named = NamedProp(PSETID_APPOINTMENT, 0x820D, None)
    a = note(Prop(0x8004, 0x0040, ft(SUBMIT), named))
    b = note(Prop(0x8123, 0x0040, ft(SUBMIT), named))
    assert canonical_bytes(a) == canonical_bytes(b)
    entry = to_parsed(a).mapi.props[f"{{{PSETID_APPOINTMENT}}}:0x820d:0x0040"]
    assert entry == {"tag": "0x80040040", "value": SUBMIT.isoformat()}


def test_name_map_parsing():
    guid = uuid.UUID(PSETID_APPOINTMENT)
    strings = struct.pack("<I", 16) + u("Keywords")
    entries = struct.pack("<IHH", 0x820D, (3 << 1), 0) + struct.pack("<IHH", 0, (2 << 1) | 1, 1)
    names = parse_name_map(guid.bytes_le, entries, strings)
    assert names[0x8000] == NamedProp(PSETID_APPOINTMENT, 0x820D, None)
    assert names[0x8001] == NamedProp(PS_PUBLIC_STRINGS, None, "Keywords")


def test_multi_valued_and_scalar_decoding():
    mv = Prop(0x1039, 0x101F, pack_multi([u("<a@x>"), u("<b@x>")]))
    assert decode(mv) == ["<a@x>", "<b@x>"]
    assert decode(Prop(0x3FF1, 0x1003, struct.pack("<ii", 7, -1))) == [7, -1]
    assert decode(Prop(0x0E1F, 0x000B, b"\x01")) is True
    assert decode(Prop(0x0E1F, 0x000B, b"\x00")) is False
    assert decode(Prop(0x3007, 0x0040, b"\0" * 8)) is None
    assert decode(Prop(0x0037, 0x001E, "Résolution".encode("cp1252")), "cp1252") == "Résolution"
    assert decode(Prop(0x1039, 0x101F, b"\xff\xff\xff\xff")) is None


def test_attachments_and_embedded_message():
    file_att = MapiAttachment(props(
        Prop(0x3705, 0x0003, struct.pack("<i", 1)),
        Prop(0x3707, 0x001F, u("Resolution 7.docx")),
        Prop(0x370E, 0x001F, u("application/vnd.openxmlformats-officedocument.wordprocessingml.document")),
        Prop(0x3701, 0x0102, b"PK\x03\x04docx"),
    ))
    inner = MapiItem(props=props(Prop(0x0037, 0x001F, u("Term sheet")), Prop(0x001A, 0x001F, u("IPM.Note"))))
    embedded = MapiAttachment(props(Prop(0x3705, 0x0003, struct.pack("<i", 5)), Prop(0x3001, 0x001F, u("Term sheet"))),
                              inner)
    item = note()
    item.attachments = [file_att, embedded]
    m = to_parsed(item)

    docx, msg = m.attachments
    assert (docx.mime_path, docx.filename, docx.data, docx.disposition) == ("1", "Resolution 7.docx", b"PK\x03\x04docx", "attachment")
    assert "0x37010102" not in docx.mapi_props
    assert docx.mapi_props["0x37050003"] == {"name": "PR_ATTACH_METHOD", "value": 1}
    assert msg.content_type == "application/vnd.ms-outlook" and msg.filename == "Term sheet"

    [(path, child)] = m.children
    assert path == "2"
    assert child.subject == "Term sheet"
    assert msg.sha256 == child.sha256


def pinned_item() -> MapiItem:
    item = note(
        Prop(0x8010, 0x001F, u("Falcon"), NamedProp(PS_PUBLIC_STRINGS, None, "Keywords")),
        Prop(0x8011, 0x0040, ft(SUBMIT), NamedProp(PSETID_APPOINTMENT, 0x820D, None)),
        Prop(0x6001, 0x0102, None),
    )
    inner = note(Prop(0x0037, 0x001F, u("Draft resolution")))
    inner.attachments = [MapiAttachment(props(
        Prop(0x3705, 0x0003, struct.pack("<i", 1)),
        Prop(0x3707, 0x001F, u("resolution.docx")),
        Prop(0x3701, 0x0102, bytes(range(256)) * 300),
    ))]
    item.attachments = [
        MapiAttachment(props(
            Prop(0x3705, 0x0003, struct.pack("<i", 1)),
            Prop(0x3707, 0x001F, u("minutes.pdf")),
            Prop(0x3701, 0x0102, b"%PDF-1.7 minutes" * 1000),
        )),
        MapiAttachment(props(Prop(0x3705, 0x0003, struct.pack("<i", 5))), inner),
    ]
    return item


PINNED_MESSAGE_SHA256 = "123e820ca324ad46048f960de55ecc9ffa3de4e6886bf255372c785891b83ac8"
PINNED_EMBEDDED_SHA256 = "6769e337bedb95c747f866ea8adb2f3ae56ece1ee8952e3249497089885718ce"


def test_canonical_hash_is_unchanged_from_the_buffered_implementation():
    item = pinned_item()
    parsed = to_parsed(item)
    assert parsed.sha256 == PINNED_MESSAGE_SHA256
    assert parsed.attachments[1].sha256 == PINNED_EMBEDDED_SHA256
    assert parsed.children[0][1].sha256 == PINNED_EMBEDDED_SHA256
    assert canonical_sha256(item) == hashlib.sha256(canonical_bytes(item)).hexdigest()


def test_non_finite_floats_are_stored_as_json_strings():
    item = note(
        Prop(0x6001, 0x0005, struct.pack("<d", float("inf"))),
        Prop(0x6002, 0x0005, struct.pack("<d", float("-inf"))),
        Prop(0x6003, 0x0005, struct.pack("<d", float("nan"))),
        Prop(0x6004, 0x1005, struct.pack("<2d", 1.5, float("inf"))),
    )
    props = to_parsed(item).mapi.props
    assert props["0x60010005"]["value"] == "Infinity"
    assert props["0x60020005"]["value"] == "-Infinity"
    assert props["0x60030005"]["value"] == "NaN"
    assert props["0x60041005"]["value"] == [1.5, "Infinity"]
    json.loads(json.dumps(props, allow_nan=False))


def test_time_properties_with_the_wrong_type_are_ignored_and_flagged():
    item = note(
        Prop(0x0039, 0x0003, struct.pack("<i", 7)),
        Prop(0x0E06, 0x0102, b"\x01\x02"),
        Prop(0x3007, 0x001F, u("yesterday")),
        Prop(0x3008, 0x1040, ft(SUBMIT) * 2),
    )
    m = to_parsed(item)
    assert m.date_utc is None
    assert m.mapi.client_submit_time is None and m.mapi.delivery_time is None
    assert m.mapi.creation_time is None and m.mapi.last_modification_time is None
    assert [d for d in m.defects if "not PT_SYSTIME" in d] == [
        "PR_CLIENT_SUBMIT_TIME has type 0x0003, not PT_SYSTIME; ignored",
        "PR_MESSAGE_DELIVERY_TIME has type 0x0102, not PT_SYSTIME; ignored",
        "PR_CREATION_TIME has type 0x001f, not PT_SYSTIME; ignored",
        "PR_LAST_MODIFICATION_TIME has type 0x1040, not PT_SYSTIME; ignored",
    ]
    assert m.mapi.props["0x00390003"]["value"] == 7


def test_correctly_typed_times_are_unaffected():
    m = to_parsed(note())
    assert m.date_utc == SUBMIT == m.mapi.client_submit_time
    assert not [d for d in m.defects if "not PT_SYSTIME" in d]
