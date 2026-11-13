import io
import struct
import zipfile
import zlib
from datetime import datetime, timedelta, timezone

from emailforensics.analysis import docmeta, metadata, sendtime, text
from emailforensics.analysis.config import load_settings

SETTINGS = load_settings(None)
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt: datetime) -> int:
    return int((dt - EPOCH).total_seconds() * 10_000_000)


def thread_index(start: datetime, deltas: list[timedelta]) -> bytes:
    head = (filetime(start) >> 16).to_bytes(6, "big")
    guid = bytes(range(16))
    blocks = b""
    for d in deltas:
        units = int(d.total_seconds() * 10_000_000) >> 18
        blocks += (units & 0x7FFFFFFF).to_bytes(4, "big") + b"\x00"
    return head + guid + blocks


def test_thread_index_decodes_start_and_reply_times():
    start = datetime(2023, 6, 1, 8, 0, tzinfo=timezone.utc)
    ti = metadata.decode_thread_index(thread_index(start, [timedelta(minutes=30), timedelta(hours=2)]))
    assert abs((ti.start_utc - start).total_seconds()) < 1
    assert len(ti.replies) == 2
    assert abs((ti.replies[0] - start - timedelta(minutes=30)).total_seconds()) < 1
    assert abs((ti.replies[1] - start - timedelta(hours=2, minutes=30)).total_seconds()) < 1
    assert ti.guid == "03020100-0504-0706-0809-0a0b0c0d0e0f"


def test_thread_index_rejects_bad_lengths():
    assert metadata.decode_thread_index(b"\x01" * 21) is None
    assert metadata.decode_thread_index(b"\x01" * 25) is None


def test_split_quoted_outlook_header():
    body = "Go ahead and sign it.\n\nJ\n\nFrom: Director Two <d2@offshore.example>\nSent: Wednesday, 14 June 2023 11:15\nTo: Jane\nSubject: RE: Falcon\n\nShould we approve?"
    q = text.split_quoted(body)
    assert q.authored == "Go ahead and sign it.\n\nJ"
    assert q.header_kind == "header"
    assert q.sent_value == "Wednesday, 14 June 2023 11:15"


def test_split_quoted_gmail_and_french():
    q = text.split_quoted("Ok.\n\nOn Wed, 14 Jun 2023 at 09:15, Jane CFO <\ncfo@group.example> wrote:\n> hi")
    assert q.authored == "Ok."
    assert "14 Jun 2023 at 09:15" in q.sent_value
    q = text.split_quoted("D'accord.\n\nDe : Jane\nEnvoyé : mercredi 14 juin 2023 11:15\nÀ : X\n")
    assert q.sent_value == "mercredi 14 juin 2023 11:15"


def test_quoted_sent_time_gives_replier_offset():
    parent_utc = datetime(2023, 6, 14, 7, 15, 20, tzinfo=timezone.utc)
    for s, expected in [
        ("Wednesday, 14 June 2023 11:15", 240),
        ("Wednesday, June 14, 2023 9:15 AM", 120),
        ("mercredi 14 juin 2023 11:15", 240),
        ("14/06/2023 09:15", 120),
        ("Wed, 14 Jun 2023 at 07:15", 0),
    ]:
        hit = text.infer_offset(text.candidate_datetimes(s), parent_utc, 4)
        assert hit is not None and hit[0] == expected, s


def test_quoted_sent_time_rejects_unrelated_time():
    parent_utc = datetime(2023, 6, 14, 7, 15, tzinfo=timezone.utc)
    assert text.infer_offset(text.candidate_datetimes("14 June 2023 11:37"), parent_utc, 4) is None


def test_phrase_matcher_uses_word_boundaries():
    m = text.PhraseMatcher({"approval": ["approved"], "instruction": ["go ahead"]})
    assert m.match("This was unapproved") == {}
    assert m.match("OK, go  ahead. Approved.") == {"approval": ["approved"], "instruction": ["go ahead"]}


def test_place_statements_and_mentions():
    p = text.PlaceMatcher(SETTINGS)
    st = p.statements("Just landed in Mauritius, then flying to Joburg on Friday.")
    assert ("present", "MU", "Just landed in Mauritius") in st
    assert any(k == "travelling_to" and c == "ZA" for k, c, _ in st)
    assert p.mentions("Flight JNB-MRU from OR Tambo") == {"MU": ["MRU"], "ZA": ["JNB", "OR Tambo"]}
    assert p.mentions("the dur of it") == {}
    assert text.routes("SA 190 JNB - MRU 14 Jun 2023", p.airport_place) == [("JNB", "MRU", 7)]


def test_boilerplate_paragraphs_are_dropped():
    body = ("Please approve the resolution.\n\nRegards\n\nThis e-mail and any attachments are confidential and may be "
            "privileged. If you have received this e-mail in error please notify the sender and delete this e-mail.")
    assert text.strip_boilerplate(body) == "Please approve the resolution.\n\nRegards"


def test_mobile_signature():
    assert text.mobile_signature("ok\n\nSent from my iPhone") == "Sent from my iPhone"
    assert text.mobile_signature("ok") is None


def test_offset_places_and_timezones():
    assert SETTINGS.place_for_offset(120) == "ZA"
    assert SETTINGS.place_for_offset(240) == "MU"
    assert SETTINGS.place_for_offset(0) is None
    assert SETTINGS.place_for_timezone("(UTC+04:00) Port Louis") == "MU"
    assert SETTINGS.place_for_timezone("South Africa Standard Time") == "ZA"


def test_client_ips_from_headers():
    headers = [
        {"name": "Received", "value": "from mx.example (40.107.1.1) by mx2 (10.0.0.1)"},
        {"name": "Received", "value": "from [192.168.1.5] (unknown [196.21.4.7]) by smtp.example"},
        {"name": "X-Originating-IP", "value": "[41.13.2.2]"},
    ]
    ips = metadata.client_ips(headers, SETTINGS)
    got = {(i["ip"], i["source"], i["scope"]) for i in ips}
    assert ("41.13.2.2", "X-Originating-IP", "public") in got
    assert ("192.168.1.5", "Received[first hop]", "private") in got
    assert ("196.21.4.7", "Received[first hop]", "public") in got
    assert not any(source == "Received[1]" for _, source, _ in got)


def test_appointment_timezone_definition():
    key = "Mauritius Standard Time"
    blob = bytes([2, 1]) + struct.pack("<HHH", 6 + 2 * len(key), 2, len(key)) + key.encode("utf-16-le") + b"\x01\x00"
    props = {
        "{00062002-0000-0000-c000-000000000046}:0x825e:0x0102": {"value": blob.hex()},
        "{00062002-0000-0000-c000-000000000046}:0x820d:0x0040": {"value": "2023-06-14T05:00:00+00:00"},
        "{00062002-0000-0000-c000-000000000046}:0x8208:0x001f": {"value": "Boardroom, Ebene"},
    }
    a = metadata.appointment("IPM.Appointment", props, "")
    assert a.tz_name == key
    assert a.location == "Boardroom, Ebene"
    assert a.start == datetime(2023, 6, 14, 5, tzinfo=timezone.utc)
    assert not a.online
    assert metadata.appointment("IPM.Note", props, "") is None


def test_sendtime_weeks_detect_two_hour_shift():
    times = []
    day = datetime(2023, 1, 2, tzinfo=timezone.utc)
    for week in range(8):
        shift = -120 if week == 5 else 0
        for d in range(5):
            base = day + timedelta(days=7 * week + d)
            times.append(base + timedelta(hours=6, minutes=shift))
            times.append(base + timedelta(hours=15, minutes=shift))
    weeks = sendtime.weekly(times, SETTINGS, "ZA")
    assert all(w.baseline_min == 360 for w in weeks)
    assert [w.place for w in weeks].count("ZA") == 7
    assert weeks[5].place == "MU" and weeks[5].shift_min == -120 and weeks[5].agreement == 1.0


def test_sendtime_noisy_weeks_are_not_labelled():
    import random

    rnd = random.Random(7)
    day = datetime(2023, 1, 2, tzinfo=timezone.utc)
    times = [day + timedelta(days=d, minutes=rnd.randint(240, 900)) for d in range(0, 7 * 30) if d % 7 < 5]
    weeks = sendtime.weekly(times, SETTINGS, "ZA")
    assert sum(1 for w in weeks if w.place == "MU") <= 1


def _docx(core: str, document: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>Group (Pty) Ltd</Company><Application>Microsoft Office Word</Application></Properties>')
        z.writestr("word/document.xml", document)
    return buf.getvalue()


def test_docx_metadata_and_revision_offsets():
    core = ('<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            "<dc:creator>Jane CFO</dc:creator><cp:lastModifiedBy>Company Sec</cp:lastModifiedBy>"
            "<dcterms:created>2023-06-10T07:00:00Z</dcterms:created><dcterms:modified>2023-06-13T09:30:00Z</dcterms:modified>"
            "</cp:coreProperties>")
    document = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
                'xmlns:w16du="http://schemas.microsoft.com/office/word/2023/wordml/word16du"><w:body>'
                '<w:ins w:id="1" w:author="Jane CFO" w:date="2023-06-12T10:00:00Z" w16du:dateUtc="2023-06-12T08:00:00Z">'
                "<w:r><w:t>Resolved that Project Falcon</w:t></w:r></w:ins></w:body></w:document>")
    m = docmeta.analyse(_docx(core, document), "resolution.docx", None)
    assert m.kind == "docx"
    assert (m.author, m.last_modified_by, m.company) == ("Jane CFO", "Company Sec", "Group (Pty) Ltd")
    assert m.created == datetime(2023, 6, 10, 7, tzinfo=timezone.utc)
    assert m.editors == [{"type": "revision", "author": "Jane CFO", "count": 1, "offsets": [120],
                          "first": "2023-06-12T10:00:00Z", "last": "2023-06-12T10:00:00Z"}]
    assert "Project Falcon" in m.text_sample


def test_pdf_dates_offsets_and_esign_ips():
    content = zlib.compress(b"BT (Certificate Of Completion) Tj (Envelope Id: 1234) Tj (Using IP Address: 102.165.3.4) Tj ET")
    data = (b"%PDF-1.4\n1 0 obj << /Length 10 /Filter /FlateDecode >>\nstream\n" + content + b"\nendstream\nendobj\n"
            b"2 0 obj << /Producer (DocuSign) /CreationDate (D:20230614091500+04'00') /Author (Ops) >> endobj\n%%EOF")
    m = docmeta.analyse(data, "Summary.pdf", "application/pdf")
    assert m.kind == "pdf"
    assert m.created == datetime(2023, 6, 14, 5, 15, tzinfo=timezone.utc) and m.created_offset == 240
    assert m.author == "Ops"
    assert "certificate of completion" in m.esign["markers"]
    assert m.ips[0]["ip"] == "102.165.3.4"


def test_document_metadata_drops_nul_characters():
    data = b"%PDF-1.4\n1 0 obj << /Producer (Acro\x00bat) /Author (A\x00B) /CreationDate (D:20230614091500Z) >> endobj\n%%EOF"
    m = docmeta.analyse(data, "x.pdf", None)
    assert m.author == "AB" and m.detail["producer"] == "Acrobat"


def test_sendtime_calibration_rejects_labels_contradicted_by_offsets():
    day = datetime(2023, 1, 2, tzinfo=timezone.utc)
    weeks = [sendtime.Week(day.date() + timedelta(weeks=i), 5, 20, 300, 900, place="MU") for i in range(6)]
    za = [(day + timedelta(weeks=i, hours=h), "ZA") for i in range(6) for h in (6, 7, 8)]
    cal = sendtime.calibrate(weeks, za, SETTINGS)
    assert cal == {"weeks_checked": 6, "agreement": 0.0, "reliable": False, "label_vs_offsets": {"MU->ZA": 6}}
    mu = [(t, "MU") for t, _ in za]
    assert sendtime.calibrate(weeks, mu, SETTINGS)["reliable"] is True
    assert sendtime.calibrate(weeks[:2], mu, SETTINGS)["reliable"] is False
