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
from emailforensics.progress import IngestProgress
from emailforensics.store import db, writer

_EXTENSIONS = {".eml": "eml", ".mbox": "mbox", ".mbx": "mbox", ".pst": "pst", ".ost": "ost", ".msg": "msg"}
_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class EvidenceChanged(RuntimeError):
    pass


@dataclass
class ItemError:
    item_path: str
    error: str


@dataclass
class FileResult:
    path: Path
    status: str
    detail: str = ""
    messages: int = 0
    attachments: int = 0
    item_errors: list[ItemError] = field(default_factory=list)


@dataclass
class IngestSummary:
    run_id: int
    files: list[FileResult] = field(default_factory=list)

    @property
    def errors(self) -> list[FileResult]:
        return [f for f in self.files if f.status == "error"]

    @property
    def item_errors(self) -> list[tuple[Path, ItemError]]:
        return [(f.path, e) for f in self.files for e in f.item_errors]


def detect_format(path: Path, explicit: bool) -> str | None:
    ext = path.suffix.lower()
    if ext in _EXTENSIONS:
        return _EXTENSIONS[ext]
    with open(path, "rb") as f:
        head = f.read(8)
    if head[:5] == b"From ":
        return "mbox"
    if head[:4] == b"!BDN":
        return "pst"
    if explicit:
        return "msg" if head == _CFB_SIGNATURE else "eml"
    return None


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


def _ingest_pst(conn, blobs, source_id: int, path: Path, result: FileResult, progress: IngestProgress) -> None:
    from emailforensics.ingest.mapi import to_parsed
    from emailforensics.ingest.pst import read_pst

    done = 0

    def tick() -> None:
        nonlocal done
        done += 1
        progress.update(done)

    progress.stage("opening", None)
    for entry in read_pst(path, on_total=lambda total: progress.stage("items", total), tick=tick):
        if entry.error is not None:
            result.item_errors.append(ItemError(entry.item_path, entry.error))
            continue
        try:
            with conn.transaction():
                msg = to_parsed(entry.item)
                m, a = writer.insert_message(
                    conn, blobs, source_id, entry.item_path, msg.sha256, msg,
                    folder_path=entry.folder_path, item_state=entry.state,
                )
        except Exception as e:
            result.item_errors.append(ItemError(entry.item_path, f"{type(e).__name__}: {e}"))
            continue
        result.messages += m
        result.attachments += a


def _ingest_msg(conn, blobs, source_id: int, path: Path, result: FileResult) -> None:
    from emailforensics.ingest.mapi import to_parsed
    from emailforensics.ingest.msg import read_msg

    msg = to_parsed(read_msg(path))
    result.messages, result.attachments = writer.insert_message(conn, blobs, source_id, "msg", msg.sha256, msg)


def _ingest_file(
    conn, case: Case, run_id: int, path: Path, fmt: str, custodian: str | None, progress: IngestProgress
) -> FileResult:
    size = path.stat().st_size
    progress.stage("hashing", size, "bytes")
    sha_before = sha256_file(path, progress.update)
    if writer.source_exists(conn, sha_before):
        return FileResult(path, "skipped", f"already ingested (sha256 {sha_before[:12]})")

    blobs = case.blobs
    result = FileResult(path, "ingested", f"sha256 {sha_before[:12]}")
    with conn.transaction():
        source_id = writer.insert_source(conn, run_id, path, fmt, sha_before, custodian)
        if fmt == "eml":
            raw = path.read_bytes()
            result.messages, result.attachments = writer.insert_message(
                conn, blobs, source_id, "eml", sha_before, parse_message(raw), byte_offset=0, byte_length=len(raw)
            )
        elif fmt in ("pst", "ost"):
            _ingest_pst(conn, blobs, source_id, path, result, progress)
        elif fmt == "msg":
            progress.stage("reading", None)
            _ingest_msg(conn, blobs, source_id, path, result)
        elif size:
            progress.stage("scanning", None)
            with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
                for entry in split_mbox(data):
                    if entry.index == 0:
                        progress.stage("messages", size, "bytes")
                    m, a = writer.insert_message(
                        conn, blobs, source_id, f"mbox:{entry.index}", sha256_bytes(entry.raw),
                        parse_message(unescape(entry.raw)),
                        byte_offset=entry.offset, byte_length=len(entry.raw), envelope_from=entry.envelope,
                    )
                    result.messages += m
                    result.attachments += a
                    progress.update(entry.offset + len(entry.raw))

        progress.stage("verifying hash", size, "bytes")
        sha_after = sha256_file(path, progress.update)
        if sha_after != sha_before:
            raise EvidenceChanged(f"{path} changed while being read ({sha_before} -> {sha_after})")

    return result


def _record(summary: IngestSummary, progress: IngestProgress, result: FileResult) -> None:
    summary.files.append(result)
    progress.end_file(result)


def ingest_paths(
    case: Case,
    inputs: list[str],
    custodian: str | None,
    argv: list[str],
    progress: IngestProgress | None = None,
) -> IngestSummary:
    progress = progress or IngestProgress()
    with db.connect(case.dsn) as conn:
        db.migrate(conn)
        summary = IngestSummary(run_id=writer.start_run(conn, __version__, argv, custodian))
        todo: list[tuple[Path, str]] = []
        for path, explicit in expand_inputs(inputs):
            try:
                fmt = detect_format(path, explicit)
            except Exception as e:
                _record(summary, progress, FileResult(path, "error", f"{type(e).__name__}: {e}"))
                continue
            if fmt is not None:
                todo.append((path, fmt))
            elif explicit:
                _record(summary, progress, FileResult(path, "unsupported", "format not recognised"))
        for number, (path, fmt) in enumerate(todo, 1):
            progress.begin_file(path, number, len(todo))
            try:
                result = _ingest_file(conn, case, summary.run_id, path, fmt, custodian, progress)
            except Exception as e:
                result = FileResult(path, "error", f"{type(e).__name__}: {e}")
            _record(summary, progress, result)
        writer.finish_run(
            conn,
            summary.run_id,
            [{"path": str(f.path.resolve()), "error": f.detail} for f in summary.errors]
            + [{"path": str(p.resolve()), "item": e.item_path, "error": e.error} for p, e in summary.item_errors],
        )
    return summary
