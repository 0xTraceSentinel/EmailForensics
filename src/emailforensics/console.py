from __future__ import annotations

import sys
import time
from pathlib import Path

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

from emailforensics.ingest.pipeline import FileResult
from emailforensics.progress import IngestProgress


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def _duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rest = divmod(seconds, 3600)
    m, s = divmod(rest, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def result_lines(f: FileResult) -> tuple[str, list[str]]:
    counts = f" {f.messages} messages, {f.attachments} attachments" if f.status == "ingested" else ""
    if f.item_errors:
        counts += f", {len(f.item_errors)} unreadable items"
    line = f"{f.status:<12}{f.path}{counts}  {f.detail}".rstrip()
    return line, [f"{'':<12}  {e.item_path}: {e.error}" for e in f.item_errors]


class _Tracker(IngestProgress):
    def __init__(self) -> None:
        self.name = ""
        self.label = ""
        self.unit = "items"
        self.total: int | None = None
        self.done = 0
        self.started = time.monotonic()

    def begin_file(self, path: Path, number: int, count: int) -> None:
        self.name = f"[{number}/{count}] {path.name}"

    def stage(self, label: str, total: int | None, unit: str = "items") -> None:
        self.label, self.total, self.unit, self.done = label, total, unit, 0
        self.started = time.monotonic()

    def update(self, done: int) -> None:
        self.done = done

    def detail(self) -> str:
        if self.total is None and not self.done:
            return ""
        elapsed = time.monotonic() - self.started
        rate = self.done / elapsed if elapsed > 0 else 0.0
        if self.unit == "bytes":
            text = f"{_size(self.done)}" + (f"/{_size(self.total)}" if self.total else "")
            return f"{text}  {_size(rate)}/s" if self.done else text
        text = f"{self.done:,}" + (f"/{self.total:,}" if self.total is not None else "")
        return f"{text}  {rate:,.0f}/s" if self.done else text

    def emit(self, line: str, err: bool = False) -> None:
        typer.echo(line, err=err)

    def end_file(self, result: FileResult) -> None:
        line, errors = result_lines(result)
        self.emit(line)
        for e in errors:
            self.emit(e, err=True)


class LiveProgress(_Tracker):
    def __init__(self) -> None:
        super().__init__()
        self.console = Console(stderr=True, highlight=False)
        self.bar = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("{task.fields[detail]}"),
            TimeElapsedColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(),
            console=self.console,
            redirect_stdout=False,
            redirect_stderr=False,
        )
        self.task = None
        self.bar.start()

    def begin_file(self, path: Path, number: int, count: int) -> None:
        super().begin_file(path, number, count)
        self._drop()
        self.task = self.bar.add_task(self.name, total=None, detail="")

    def stage(self, label: str, total: int | None, unit: str = "items") -> None:
        super().stage(label, total, unit)
        if self.task is not None:
            self.bar.reset(self.task, total=total, description=f"{self.name} {label}", detail=self.detail())

    def update(self, done: int) -> None:
        super().update(done)
        if self.task is not None:
            self.bar.update(self.task, completed=done, detail=self.detail())

    def emit(self, line: str, err: bool = False) -> None:
        if (sys.stderr if err else sys.stdout).isatty():
            self.console.print(line, markup=False, soft_wrap=True)
        else:
            super().emit(line, err)

    def end_file(self, result: FileResult) -> None:
        self._drop()
        super().end_file(result)

    def _drop(self) -> None:
        if self.task is not None:
            self.bar.remove_task(self.task)
            self.task = None

    def close(self) -> None:
        self._drop()
        self.bar.stop()


class LogProgress(_Tracker):
    def __init__(self, every: float = 15.0) -> None:
        super().__init__()
        self.every = every
        self.last = 0.0

    def stage(self, label: str, total: int | None, unit: str = "items") -> None:
        super().stage(label, total, unit)
        self._log(force=True)

    def update(self, done: int) -> None:
        super().update(done)
        self._log()

    def _log(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last < self.every:
            return
        self.last = now
        line = f"{self.name} {self.label}: {self.detail()}"
        if self.total and self.done:
            pct = self.done / self.total
            elapsed = now - self.started
            line += f" ({pct:.1%}, elapsed {_duration(elapsed)}, eta {_duration(elapsed / pct - elapsed)})"
        typer.echo(line, err=True)


class QuietProgress(_Tracker):
    pass


def make_progress(enabled: bool) -> IngestProgress:
    if not enabled:
        return QuietProgress()
    return LiveProgress() if sys.stderr.isatty() else LogProgress()
