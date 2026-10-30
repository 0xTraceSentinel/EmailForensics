import os
import shutil
import uuid
from pathlib import Path

import pytest

from emailforensics.case import Case, create_case
from emailforensics.hashing import sha256_file
from emailforensics.ingest.pipeline import ingest_paths
from emailforensics.store import db

FIXTURES = Path(__file__).parent / "fixtures"
TEST_DSN = os.environ.get("EMAILFORENSICS_TEST_DSN")

pytestmark = pytest.mark.skipif(not TEST_DSN, reason="EMAILFORENSICS_TEST_DSN not set")


@pytest.fixture
def case(tmp_path, monkeypatch):
    monkeypatch.setenv("EMAILFORENSICS_DSN", TEST_DSN)
    c = create_case(tmp_path / "case", name=f"test-{uuid.uuid4().hex[:8]}")
    yield c
    db.drop_database(TEST_DSN, c.database)


@pytest.fixture
def evidence(tmp_path):
    d = tmp_path / "exports"
    shutil.copytree(FIXTURES, d)
    return d


def test_ingest_records_provenance_and_is_idempotent(case, evidence):
    hashes_before = {p.name: sha256_file(p) for p in evidence.iterdir()}

    first = ingest_paths(case, [str(evidence)], custodian="cfo", argv=["test"])
    assert not first.errors
    assert {f.path.name for f in first.files if f.status == "ingested"} == set(hashes_before)

    with db.connect(case.dsn) as conn:
        sources = dict(conn.execute("SELECT file_name, sha256 FROM source_file"))
        assert sources == hashes_before

        assert conn.execute("SELECT count(*) FROM message").fetchone()[0] == 6

        row = conn.execute(
            "SELECT m.item_path, m.date_offset_minutes, m.headers->0->>'name', s.custodian"
            " FROM message m JOIN source_file s ON s.id = m.source_file_id"
            " WHERE m.rfc_message_id = '<falcon-001@group.example>'"
        ).fetchone()
        assert row == ("eml", 120, "Received", "cfo")

        child = conn.execute(
            "SELECT c.item_path, p.rfc_message_id FROM message c JOIN message p ON p.id = c.parent_id"
        ).fetchone()
        assert child == ("eml/rfc822:2", "<fwd-001@offshore.example>")

        assert conn.execute(
            "SELECT count(*) FROM message WHERE body_tsv @@ plainto_tsquery('simple', 'sandton')"
        ).fetchone()[0] == 1

        att_shas = [r[0] for r in conn.execute("SELECT sha256 FROM attachment")]
    for sha in att_shas:
        assert case.blobs.path(sha).exists()

    second = ingest_paths(Case.load(case.root), [str(evidence)], custodian="cfo", argv=["test"])
    assert {f.status for f in second.files} == {"skipped"}

    assert {p.name: sha256_file(p) for p in evidence.iterdir()} == hashes_before
