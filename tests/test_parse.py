from datetime import datetime, timezone
from pathlib import Path

from emailforensics.hashing import sha256_bytes
from emailforensics.ingest.parse import parse_message

FIXTURES = Path(__file__).parent / "fixtures"


def parse(name: str):
    return parse_message((FIXTURES / name).read_bytes())


def test_date_is_normalised_to_utc_and_offset_kept():
    m = parse("board_pack.eml")
    assert m.date_raw == "Wed, 14 Jun 2023 09:15:00 +0200"
    assert m.date_utc == datetime(2023, 6, 14, 7, 15, tzinfo=timezone.utc)
    assert m.date_offset_minutes == 120


def test_headers_are_raw_ordered_and_keep_duplicates():
    m = parse("board_pack.eml")
    names = [n for n, _ in m.headers]
    assert names[:3] == ["Received", "Received", "From"]
    assert ("X-Mailer", "Microsoft Outlook 16.0") in m.headers


def test_identifiers_and_threading_fields():
    m = parse("board_pack.eml")
    assert m.rfc_message_id == "<falcon-001@group.example>"
    assert m.in_reply_to == "<falcon-000@group.example>"
    assert m.references == ["<falcon-root@group.example>", "<falcon-000@group.example>"]


def test_encoded_words_and_addresses():
    m = parse("board_pack.eml")
    assert m.subject == "Board pack – Project Falcon"
    assert m.from_addr == [{"name": "Jane CFO", "address": "cfo@group.example"}]
    assert m.sender_addr == [{"name": "Assistant", "address": "pa@group.example"}]
    assert [a["address"] for a in m.to_addrs] == ["director1@offshore.example", "director2@offshore.example"]
    assert m.cc_addrs == [{"name": "André Legal", "address": "legal@group.example"}]


def test_body_and_attachments():
    m = parse("board_pack.eml")
    assert "Please approve" in m.body_text
    assert m.body_html is None
    by_name = {a.filename: a for a in m.attachments}
    assert set(by_name) == {"minutes.txt", "data.bin"}
    assert by_name["data.bin"].data == b"hello"
    assert by_name["data.bin"].sha256 == sha256_bytes(b"hello")
    assert by_name["data.bin"].mime_path == "3"
    assert by_name["minutes.txt"].mime_path == "2"


def test_embedded_message_becomes_child():
    m = parse("forwarded.eml")
    assert m.date_offset_minutes == 240
    assert len(m.attachments) == 1 and m.attachments[0].content_type == "message/rfc822"
    [(path, child)] = m.children
    assert path == "2"
    assert child.rfc_message_id == "<ts-001@bank.example>"
    assert child.date_offset_minutes == 60
    assert "Sandton" in child.body_text


def test_unknown_zone_is_flagged():
    raw = b"From: a@example\r\nDate: Wed, 14 Jun 2023 00:00:00 -0000\r\n\r\nx\r\n"
    m = parse_message(raw)
    assert m.date_offset_minutes is None
    assert m.date_utc == datetime(2023, 6, 14, tzinfo=timezone.utc)
    assert any("-0000" in d for d in m.defects)


def test_garbage_date_does_not_crash():
    m = parse_message(b"From: a@example\r\nDate: not a date\r\n\r\nx\r\n")
    assert m.date_utc is None
    assert "unparseable Date header" in m.defects
