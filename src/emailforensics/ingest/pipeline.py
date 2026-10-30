from __future__ import annotations

import glob
import mmap
from dataclasses import dataclass, field
from pathlib import Path

from emailforensics import __version__
from emailforensics.case import Case
from emailforensics.hashing import sha256_bytes, sha256_file
from emailforensics.ingest.mbox import split_mbox, unescape
from emailforensics.ingest.parse import parse_message
from emailforensics.store import db, writer

_EXTENSIONS = {".eml": "eml", ".mbox": "mbox", ".mbx": "mbox"}
_LATER = {".pst", ".ost", ".msg"}


class EvidenceChanged(RuntimeError):
    pass


@dataclass
class FileResult:
    path: Path
    status: str
    detail: str = ""
    messages: int = 0
    attachments: int = 0


@dataclass
class IngestSummary:
    run_id: int
    files: list[FileResult] = field(default_factory=list)

    @property
    def errors(self) -> list[FileResult]:
        return [f for f in self.files if f.status == "error"]


def detect_format(path: Path, explicit: bool) -> str | None:
    ext = path.suffix.lower()
    if ext in _EXTENSIONS:
        return _EXTENSIONS[ext]
    if ext in _LATER:
        return None
    with open(path, "rb") as f:
        if f.read(5) == b"From ":
            return "mbox"
    return "eml" if explicit else None


def expand_inputs(inputs: list[str]) -> list[tuple[Path, bool]]:
    found: dict[Path, bool] = {}
    for arg in inputs:
        p = Path(arg)
        if p.is_file():
            found[p] = True
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file():
                    found.setdefault(f, False)
        else:
            for match in glob.glob(arg, recursive=True):
                if Path(match).is_file():
                    found[Path(match)] = True
    return sorted(found.items(), key=lambda kv: str(kv[0]))


def _ingest_file(conn, case: Case, run_id: int, path: Path, fmt: str, custodian: str | None) -> FileResult:
    sha_before = sha256_file(path)
    if writer.source_exists(conn, sha_before):
        return FileResult(path, "skipped", f"already ingested (sha256 {sha_before[:12]})")

    blobs = case.blobs
    n_msgs = n_atts = 0
    with conn.transaction():
        source_id = writer.insert_source(conn, run_id, path, fmt, sha_before, custodian)
        if fmt == "eml":
            raw = path.read_bytes()
            m, a = writer.insert_message(
                conn, blobs, source_id, "eml", sha_before, parse_message(raw), byte_offset=0, byte_length=len(raw)
            )
            n_msgs, n_atts = m, a
        elif path.stat().st_size:
            with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for entry in split_mbox(data):
                    m, a = writer.insert_message(
                        conn, blobs, source_id, f"mbox:{entry.index}", sha256_bytes(entry.raw),
                        parse_message(unescape(entry.raw)),
                        byte_offset=entry.offset, byte_length=len(entry.raw), envelope_from=entry.envelope,
                    )
                    n_msgs += m
                    n_atts += a

        sha_after = sha256_file(path)
        if sha_after != sha_before:
            raise EvidenceChanged(f"{path} changed while being read ({sha_before} -> {sha_after})")

    return FileResult(path, "ingested", f"sha256 {sha_before[:12]}", n_msgs, n_atts)


def ingest_paths(case: Case, inputs: list[str], custodian: str | None, argv: list[str]) -> IngestSummary:
    with db.connect(case.dsn) as conn:
        db.migrate(conn)
        summary = IngestSummary(run_id=writer.start_run(conn, __version__, argv, custodian))
        for path, explicit in expand_inputs(inputs):
            try:
                fmt = detect_format(path, explicit)
                if fmt is None:
                    if explicit or path.suffix.lower() in _LATER:
                        summary.files.append(FileResult(path, "unsupported", "format not supported yet"))
                    continue
                summary.files.append(_ingest_file(conn, case, summary.run_id, path, fmt, custodian))
            except Exception as e:
                summary.files.append(FileResult(path, "error", f"{type(e).__name__}: {e}"))
        writer.finish_run(
            conn,
            summary.run_id,
            [{"path": str(f.path.resolve()), "error": f.detail} for f in summary.errors],
        )
    return summary
