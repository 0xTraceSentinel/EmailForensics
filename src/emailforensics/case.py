from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from psycopg.conninfo import make_conninfo

from emailforensics import __version__
from emailforensics.blobs import BlobStore
from emailforensics.store import db

CASE_FILE = "case.json"
DEFAULT_DSN = "postgresql://emailforensics:emailforensics@localhost:5432/postgres"


def server_dsn() -> str:
    return os.environ.get("EMAILFORENSICS_DSN", DEFAULT_DSN)


def database_name(case_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", case_name.lower()).strip("_") or "case"
    return f"ef_{slug}"[:63]


@dataclass
class Case:
    root: Path
    name: str
    database: str

    @property
    def dsn(self) -> str:
        return make_conninfo(server_dsn(), dbname=self.database)

    @property
    def blobs(self) -> BlobStore:
        return BlobStore(self.root / "blobs")

    @classmethod
    def load(cls, root: Path) -> Case:
        f = root / CASE_FILE
        if not f.exists():
            raise FileNotFoundError(f"{root} is not a case folder (no {CASE_FILE}); run `emailforensics init` first")
        data = json.loads(f.read_text(encoding="utf-8"))
        return cls(root=root, name=data["name"], database=data["database"])


def create_case(root: Path, name: str | None = None) -> Case:
    if (root / CASE_FILE).exists():
        raise FileExistsError(f"{root} is already a case folder")
    name = name or root.resolve().name
    case = Case(root=root, name=name, database=database_name(name))

    db.create_database(server_dsn(), case.database)
    with db.connect(case.dsn) as conn:
        db.migrate(conn)

    root.mkdir(parents=True, exist_ok=True)
    (root / "blobs").mkdir(exist_ok=True)
    (root / CASE_FILE).write_text(
        json.dumps(
            {
                "name": case.name,
                "database": case.database,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "tool_version": __version__,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return case
