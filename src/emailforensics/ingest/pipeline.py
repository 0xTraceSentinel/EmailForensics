from __future__ import annotations

import glob
import mmap
from dataclasses import dataclass, field
from pathlib import Path

import psycopg

from emailforensics import __version__
from emailforensics.case import Case
from emailforensics.hashing import sha256_bytes, sha256_file
from emailforensics.ingest.mbox import split_mbox, unescape
from emailforensics.ingest.parse import parse_message
from emailforensics.memory import NO_GUARD, Guard, MemoryPressure
from emailforensics.progress import IngestProgress
from emailforensics.store import db, writer

_EXTENSIONS = {".eml": "eml", ".mbox": "mbox", ".mbx": "mbox", ".pst": "pst", ".ost": "ost", ".msg": "msg"}
_CFB_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


BATCH_ITEMS = 500
BATCH_BYTES = 32 << 20
LOW_MEMORY_BATCH_ITEMS = 50
LOW_MEMORY_BATCH_BYTES = 4 << 20
INTERRUPTIONS = (MemoryPressure, MemoryError, psycopg.OperationalError)


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


class _Batch:
    def __init__(self, conn, blobs, source_id: int, result: FileResult, isolate: bool,
                 checkpoint: bool = False, guard: Guard = NO_GUARD) -> None:
        self.conn, self.blobs, self.source_id, self.result, self.isolate = conn, blobs, source_id, result, isolate
        self.checkpoint, self.guard = checkpoint, guard
        self.items: list[tuple[int, writer.NewMessage]] = []
        self.size = 0
        self.errors: list[tuple[int, ItemError]] = []
        self.unsaved: list[tuple[int, ItemError]] = []
        self.done = 0

    def add(self, item: writer.NewMessage, seq: int = 0) -> None:
        self.items.append((seq, item))
        self.done = max(self.done, seq + 1)
        self.size += writer.payload_bytes(item.msg)
        low = self.guard.check()
        if (len(self.items) >= (LOW_MEMORY_BATCH_ITEMS if low else BATCH_ITEMS)
                or self.size >= (LOW_MEMORY_BATCH_BYTES if low else BATCH_BYTES)):
            self.flush()

    def error(self, seq: int, item_path: str, error: str) -> None:
        self.errors.append((seq, ItemError(item_path, error)))
        self.unsaved.append((seq, ItemError(item_path, error)))
        self.done = max(self.done, seq + 1)

    def flush(self) -> None:
        pending, self.items, self.size = self.items, [], 0
        if not pending and not (self.checkpoint and self.unsaved):
            return
        if self.checkpoint:
            with self.conn.transaction():
                self._insert(pending)
                errors, self.unsaved = self.unsaved, []
                writer.checkpoint_source(self.conn, self.source_id, self.done,
                                         [{"seq": s, "item": e.item_path, "error": e.error} for s, e in errors])
            return
        self._insert(pending)

    def _insert(self, pending: list[tuple[int, writer.NewMessage]]) -> None:
        if not pending:
            return
        items = [item for _, item in pending]
        if not self.isolate:
            self._count(writer.insert_messages(self.conn, self.blobs, self.source_id, items))
            return
        try:
            with self.conn.transaction():
                counts = writer.insert_messages(self.conn, self.blobs, self.source_id, items)
        except INTERRUPTIONS:
            raise
        except Exception:
            for seq, item in pending:
                try:
                    with self.conn.transaction():
                        counts = writer.insert_messages(self.conn, self.blobs, self.source_id, [item])
                except INTERRUPTIONS:
                    raise
                except Exception as e:
                    self.error(seq, item.item_path, f"{type(e).__name__}: {e}")
                    continue
                self._count(counts)
            return
        self._count(counts)

    def finish(self) -> None:
        self.flush()
        self.result.item_errors.extend(e for _, e in sorted(self.errors, key=lambda se: se[0]))
        self.errors = []

    def _count(self, counts: tuple[int, int]) -> None:
        self.result.messages += counts[0]
        self.result.attachments += counts[1]


def _ingest_pst(conn, blobs, source_id: int, path: Path, result: FileResult, progress: IngestProgress,
                skip: int = 0, guard: Guard = NO_GUARD) -> None:
    from emailforensics.ingest.mapi import to_parsed
    from emailforensics.ingest.pst import read_pst

    done = 0

    def tick() -> None:
        nonlocal done
        done += 1
        progress.update(done)

    progress.stage("opening", None)
    batch = _Batch(conn, blobs, source_id, result, isolate=True, checkpoint=True, guard=guard)
    entries = read_pst(path, on_total=lambda total: progress.stage("items", total), tick=tick, skip=skip)
    for index, entry in enumerate(entries):
        seq = entry.seq if entry.seq >= 0 else index
        if entry.error is not None:
            batch.error(seq, entry.item_path, entry.error)
            continue
        try:
            msg = to_parsed(entry.item)
        except Exception as e:
            batch.error(seq, entry.item_path, f"{type(e).__name__}: {e}")
            continue
        new = writer.NewMessage(entry.item_path, msg.sha256, msg, folder_path=entry.folder_path, item_state=entry.state)
        batch.add(new, seq)
    batch.finish()


def _ingest_msg(conn, blobs, source_id: int, path: Path, result: FileResult) -> None:
    from emailforensics.ingest.mapi import to_parsed
    from emailforensics.ingest.msg import read_msg

    msg = to_parsed(read_msg(path))
    result.messages, result.attachments = writer.insert_message(conn, blobs, source_id, "msg", msg.sha256, msg)


RESUMABLE = ("pst", "ost", "mbox")


def _ingest_mbox(conn, blobs, source_id: int, path: Path, size: int, result: FileResult, progress: IngestProgress,
                 skip: int = 0, guard: Guard = NO_GUARD) -> None:
    progress.stage("scanning", None)
    batch = _Batch(conn, blobs, source_id, result, isolate=False, checkpoint=True, guard=guard)
    with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
        for entry in split_mbox(data):
            if entry.index == 0:
                progress.stage("messages", size, "bytes")
            if entry.index < skip:
                continue
            batch.add(writer.NewMessage(
                f"mbox:{entry.index}", sha256_bytes(entry.raw), parse_message(unescape(entry.raw)),
                byte_offset=entry.offset, byte_length=len(entry.raw), envelope_from=entry.envelope,
            ), entry.index)
            progress.update(entry.offset + len(entry.raw))
        batch.finish()


def _ingest_file(
    conn, case: Case, run_id: int, path: Path, fmt: str, custodian: str | None, progress: IngestProgress,
    guard: Guard = NO_GUARD,
) -> FileResult:
    size = path.stat().st_size
    progress.stage("hashing", size, "bytes")
    sha_before = sha256_file(path, progress.update)
    state = writer.source_state(conn, sha_before)
    if state is not None and state.status == "complete":
        return FileResult(path, "skipped", f"already ingested (sha256 {sha_before[:12]})")

    blobs = case.blobs
    result = FileResult(path, "ingested", f"sha256 {sha_before[:12]}")
    if fmt not in RESUMABLE or not size:
        with conn.transaction():
            source_id = writer.insert_source(conn, run_id, path, fmt, sha_before, custodian)
            if fmt == "eml":
                raw = path.read_bytes()
                result.messages, result.attachments = writer.insert_message(
                    conn, blobs, source_id, "eml", sha_before, parse_message(raw), byte_offset=0, byte_length=len(raw)
                )
            elif fmt == "msg":
                progress.stage("reading", None)
                _ingest_msg(conn, blobs, source_id, path, result)
            progress.stage("verifying hash", size, "bytes")
            sha_after = sha256_file(path, progress.update)
            if sha_after != sha_before:
                raise EvidenceChanged(f"{path} changed while being read ({sha_before} -> {sha_after})")
        return result

    skip = 0
    if state is None:
        source_id = writer.insert_source(conn, run_id, path, fmt, sha_before, custodian, status="in_progress")
    else:
        if (state.custodian or None) != (custodian or None):
            raise ValueError(f"{path.name} was partly ingested with custodian {state.custodian!r}; "
                             f"resume with --custodian {state.custodian}")
        source_id, skip = state.id, state.items_done
        writer.resume_source(conn, source_id, run_id)
        result.detail += f", resumed after {skip:,} items"
        result.item_errors.extend(ItemError(e["item"], e["error"]) for e in sorted(state.item_errors, key=lambda e: e["seq"]))
    if fmt in ("pst", "ost"):
        _ingest_pst(conn, blobs, source_id, path, result, progress, skip=skip, guard=guard)
    else:
        _ingest_mbox(conn, blobs, source_id, path, size, result, progress, skip=skip, guard=guard)

    progress.stage("verifying hash", size, "bytes")
    sha_after = sha256_file(path, progress.update)
    with conn.transaction():
        if sha_after != sha_before:
            writer.delete_source(conn, source_id)
            raise EvidenceChanged(f"{path} changed while being read ({sha_before} -> {sha_after})")
        writer.complete_source(conn, source_id)
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
    guard: Guard = NO_GUARD,
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
                result = _ingest_file(conn, case, summary.run_id, path, fmt, custodian, progress, guard)
            except INTERRUPTIONS:
                try:
                    writer.interrupt_run(conn, summary.run_id)
                except psycopg.Error:
                    pass
                raise
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
