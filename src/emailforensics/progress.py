from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from emailforensics.ingest.pipeline import FileResult


class IngestProgress:
    def begin_file(self, path: Path, number: int, count: int) -> None:
        pass

    def stage(self, label: str, total: int | None, unit: str = "items") -> None:
        pass

    def update(self, done: int) -> None:
        pass

    def end_file(self, result: FileResult) -> None:
        pass

    def close(self) -> None:
        pass
