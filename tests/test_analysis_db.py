import os
import uuid
from datetime import date, datetime, timezone

import pytest

from emailforensics.analysis.config import Decision, Person, load_settings
from emailforensics.analysis.registers import save_decisions, save_people
from emailforensics.analysis.run import analyze_case
from emailforensics.case import create_case
from emailforensics.ingest.parse import Attachment, MapiFields, parse_message
from emailforensics.report import build_report
from emailforensics.store import db, writer
from test_analysis import _docx

TEST_DSN = os.environ.get("EMAILFORENSICS_TEST_DSN")

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="EMAILFORENSICS_TEST_DSN not set")


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAILFORENSICS_DSN", TEST_DSN)
    c = create_case(tmp_path / "case", name=f"test-{uuid.uuid4().hex[:8]}")
    yield c
    db.drop_database(TEST_DSN, c.database)


def eml(headers: dict, body: str) -> bytes:
    lines = [f"{k}: {v}" for k, v in headers.items()]
    return ("\r\n".join(lines) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body).encode()


def as_sent_item(raw: bytes, submit: datetime, props: dict | None = None, message_class: str = "IPM.Note"):
    msg = parse_message(raw)
    msg.headers = []
    msg.date_raw, msg.date_utc, msg.date_offset_minutes = None, submit, None
    msg.mapi = MapiFields(message_class, submit, None, submit, submit, None, [], None, None, [], props or {})
    return msg


CORE = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
        "<dc:creator>Jane CFO</dc:creator><cp:lastModifiedBy>Jane CFO</cp:lastModifiedBy>"
        "<dcterms:created>2023-06-10T07:00:00Z</dcterms:created><dcterms:modified>2023-06-13T09:30:00Z</dcterms:modified>"
        "</cp:coreProperties>")
DOC = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
       "<w:p><w:r><w:t>Board resolution: Project Falcon</w:t></w:r></w:p></w:body></w:document>")


def load_mailbox(case, tmp_path):
    src = tmp_path / "exec.pst"
    src.write_bytes(b"!BDN test")
    sent, inbox = ["Top of Information Store", "Sent Items"], ["Top of Information Store", "Inbox"]
    a = parse_message(eml({
        "Received": "from [10.0.0.2] (unknown [102.112.1.9]) by mx.offshore.example",
        "From": "Director Two <d2@offshore.example>", "To": "cfo@group.example",
        "Subject": "Project Falcon board pack", "Date": "Wed, 14 Jun 2023 11:15:00 +0400",
        "Message-ID": "<a@offshore.example>",
    }, "Should we approve the Project Falcon resolution? I have a concern about the price."))
    a.attachments.append(Attachment("2", "Falcon resolution.docx", "application/octet-stream", "attachment", None, _docx(CORE, DOC)))
    b = as_sent_item(eml({
        "From": "Jane CFO <cfo@group.example>", "To": "d2@offshore.example", "Subject": "RE: Project Falcon board pack",
        "Message-ID": "<b@group.example>", "In-Reply-To": "<a@offshore.example>",
    }, "Go ahead and sign it, it is a formality. We have already agreed.\n\nFrom: Director Two\n"
       "Sent: Wednesday, 14 June 2023 09:15\nTo: Jane CFO\nSubject: Project Falcon board pack\n\nShould we approve?"),
        datetime(2023, 6, 14, 8, 0, 5, tzinfo=timezone.utc))
    c_sent = as_sent_item(eml({
        "From": "Jane CFO <cfo@group.example>", "To": "bank@bank.example", "Cc": "cfo@group.example",
        "Subject": "Falcon funding", "Message-ID": "<c@group.example>",
    }, "Please proceed with the Project Falcon drawdown.\n\nSent from my iPhone"), datetime(2023, 6, 15, 6, 0, tzinfo=timezone.utc))
    c_inbox = parse_message(eml({
        "From": "Jane CFO <cfo@group.example>", "To": "bank@bank.example", "Cc": "cfo@group.example",
        "Subject": "Falcon funding", "Date": "Thu, 15 Jun 2023 08:00:00 +0200", "Message-ID": "<c@group.example>",
    }, "Please proceed with the Project Falcon drawdown.\n\nSent from my iPhone"))
    d = as_sent_item(eml({
        "From": "Jane CFO <cfo@group.example>", "To": "pa@group.example", "Subject": "Travel", "Message-ID": "<d@group.example>",
    }, "Just landed in Mauritius. Back on Friday."), datetime(2023, 6, 20, 9, 0, tzinfo=timezone.utc))
    with db.connect(case.dsn) as conn:
        run = writer.start_run(conn, "test", ["test"], "exec")
        sid = writer.insert_source(conn, run, src, "pst", "0" * 64, "exec")
        writer.insert_messages(conn, case.blobs, sid, [
            writer.NewMessage("pst:1", a.sha256, a, folder_path=inbox, item_state="live"),
            writer.NewMessage("pst:2", "b" * 64, b, folder_path=sent, item_state="live"),
            writer.NewMessage("pst:3", "c" * 64, c_sent, folder_path=sent, item_state="live"),
            writer.NewMessage("pst:4", c_inbox.sha256, c_inbox, folder_path=inbox, item_state="live"),
            writer.NewMessage("pst:5", "d" * 64, d, folder_path=sent, item_state="recoverable"),
        ])
        return {r[1]: r[0] for r in conn.execute("SELECT id, item_path FROM message")}


def test_analysis_and_report_end_to_end(case, tmp_path):
    ids = load_mailbox(case, tmp_path)
    save_people(case, [
        Person("exec", "Jane CFO", ["Jane CFO"], ["cfo@group.example"], "ZA", "CFO", True, True),
        Person("d2", "Director Two", ["Director Two"], ["d2@offshore.example"], "MU", "Director", True, False),
    ])
    save_decisions(case, [Decision("D1", "Acquire Falcon", date(2023, 6, 14), "Port Louis board meeting", "MU", "Minutes p1",
                                   ["Project Falcon"], date(2023, 6, 1), date(2023, 6, 30))])
    stats = analyze_case(case, load_settings(None), ["test"])
    assert stats["offsets_from_copies"] == 1
    assert stats["offsets_from_quoted_headers"] == 1

    with db.connect(case.dsn) as conn:
        def row(path):
            return conn.execute(
                "SELECT a.sender_person, a.custodian_sent, a.offset_minutes, a.offset_method, a.place, a.place_method, a.roles, a.mobile"
                " FROM message_analysis a WHERE a.msg_id = %s", (ids[path],)).fetchone()

        assert row("pst:1")[:6] == ("d2", False, 240, "date_header", "MU", "date_header")
        assert row("pst:2")[:6] == ("exec", True, 120, "quoted_header", "ZA", "quoted_header")
        assert set(row("pst:2")[6]) >= {"formality", "instruction"}
        assert row("pst:3")[2:5] == (120, "date_header_copy", "ZA") and row("pst:3")[7] is True
        assert row("pst:5")[4:6] == ("MU", "statement_present")

        linked = {r[0] for r in conn.execute("SELECT msg_id FROM decision_message WHERE decision_id = 'D1'")}
        assert {ids["pst:1"], ids["pst:2"], ids["pst:3"]} <= linked

        meta = conn.execute("SELECT author, company, created FROM attachment_meta").fetchone()
        assert meta == ("Jane CFO", "Group (Pty) Ltd", datetime(2023, 6, 10, 7, tzinfo=timezone.utc))
        kinds = {r[0] for r in conn.execute("SELECT kind FROM anomaly")}
        assert "document_created_before_formal_date" in kinds
        reasons = {r[0] for r in conn.execute("SELECT reason FROM review_item")}
        assert {"formality", "geolocate_ip"} <= reasons
        assert conn.execute("SELECT count(*) FROM location_evidence WHERE method = 'statement_present' AND place = 'MU'").fetchone()[0] == 1

    index, stale = build_report(case, load_settings(None), tmp_path / "report", verify=False)
    assert not stale
    page = index.read_text(encoding="utf-8")
    assert "Stale analysis" not in page
    assert "Acquire Falcon" in page and "Indicator matrix" in page
    assert (tmp_path / "report" / "csv" / "timeline_D1.csv").exists()
    assert (tmp_path / "report" / "csv" / "review_queue.csv").exists()

    save_decisions(case, [Decision("D1", "Acquire Falcon", date(2023, 6, 14), None, "MU", None, ["Project Falcon"], None, None)])
    index, stale = build_report(case, load_settings(None), tmp_path / "report", verify=False)
    assert stale and "Stale analysis" in index.read_text(encoding="utf-8")
    analyze_case(case, load_settings(None), ["test"])
    assert build_report(case, load_settings(None), tmp_path / "report", verify=False)[1] is False
