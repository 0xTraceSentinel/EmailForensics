from pathlib import Path

import pytest

from emailforensics.ingest.mbox import split_mbox, unescape
from emailforensics.ingest.parse import parse_message

FIXTURES = Path(__file__).parent / "fixtures"


def entries():
    return list(split_mbox((FIXTURES / "sample.mbox").read_bytes()))


def test_splits_only_on_from_lines_after_blank_lines():
    es = entries()
    assert [e.index for e in es] == [0, 1, 2]
    assert b"From here the board just needs to sign off." in es[0].raw


def test_offsets_point_at_the_stored_bytes():
    data = (FIXTURES / "sample.mbox").read_bytes()
    for e in entries():
        assert data[e.offset : e.offset + len(e.raw)] == e.raw
        assert e.raw.startswith(b"From: ")


def test_envelope_and_separator_blank_line():
    first = entries()[0]
    assert first.envelope == "cfo@group.example Tue Jun 13 08:00:00 2023"
    assert first.raw.endswith(b"sign off.\n")


def test_from_quoting_is_undone_for_parsing_only():
    second = entries()[1]
    assert b"\n>From the desk" in second.raw
    assert "\nFrom the desk" in parse_message(unescape(second.raw)).body_text


def test_rejects_non_mbox():
    with pytest.raises(ValueError):
        list(split_mbox(b"From: a@example\n\nnot an mbox\n"))
