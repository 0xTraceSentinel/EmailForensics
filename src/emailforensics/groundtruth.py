from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from emailforensics.analysis.zones import offset_at
from emailforensics.case import Case
from emailforensics.store import db


@dataclass
class Test:
    tag: str
    client: str
    device: str | None
    account: str | None
    device_timezone: str | None
    place: str | None
    notes: str | None


def load_truth(path: Path) -> list[Test]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = data.get("tests") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError(f"{path}: expected a 'tests:' list of entries (see docs/examples/truth.yaml)")
    out = []
    for i, r in enumerate(rows, 1):
        if not isinstance(r, dict) or not r.get("tag"):
            raise ValueError(f"{path}: test {i} must be a mapping with at least a 'tag'")
        out.append(Test(
            tag=str(r["tag"]),
            client=str(r.get("client", "")),
            device=r.get("device"),
            account=r.get("account"),
            device_timezone=r.get("device_timezone"),
            place=str(r["place"]).upper() if r.get("place") else None,
            notes=r.get("notes"),
        ))
    return out


COLUMNS = [
    "tag", "client", "account", "copy", "folder", "item_path", "date_raw", "offset", "expected_offset", "offset_ok",
    "writer_path", "writer_device", "expected_device", "device_ok", "clock", "skew_min", "informative", "place",
    "expected_place", "place_ok", "basis",
]


def _off(m):
    if m is None:
        return ""
    sign = "+" if m >= 0 else "-"
    return f"{sign}{abs(m) // 60:02d}{abs(m) % 60:02d}"


def evaluate(case: Case, tests: list[Test]) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    with db.connect(case.dsn) as conn:
        if conn.execute("SELECT count(*) FROM message_analysis").fetchone()[0] == 0:
            raise RuntimeError("no analysis results; run `emailforensics analyze` first")
        for t in tests:
            found = conn.execute(
                "SELECT m.id, m.item_path, m.folder_path, m.date_raw, coalesce(a.sent_utc, m.date_utc), a.offset_minutes,"
                " a.offset_method, a.writer, a.clock_check, a.clock_skew_min, a.offset_candidates, a.place, a.custodian_sent"
                " FROM message m JOIN message_analysis a ON a.msg_id = m.id"
                " WHERE m.parent_id IS NULL AND m.subject ILIKE %s ORDER BY m.id",
                (f"%[{t.tag}]%",),
            ).fetchall()
            if not found:
                rows.append({"tag": t.tag, "client": t.client, "account": t.account, "copy": "NOT FOUND"})
                continue
            for mid, path, folder, raw, at, off, method, writer, clock, skew, cand, place, sent in found:
                expected = offset_at(t.device_timezone, at) if (t.device_timezone and at) else None
                w = writer or {}
                d = (cand or {}).get("date") or {}
                rows.append({
                    "tag": t.tag, "client": t.client, "account": t.account,
                    "copy": "sent item" if sent else "received copy",
                    "folder": "/".join(folder or []), "item_path": path, "date_raw": raw or "",
                    "offset": f"{_off(off)} ({method})" if off is not None else "none",
                    "expected_offset": _off(expected),
                    "offset_ok": "" if expected is None or off is None else ("yes" if off == expected else ("UTC" if off == 0 else "no")),
                    "writer_path": w.get("path", ""), "writer_device": w.get("device", ""),
                    "expected_device": t.device or "",
                    "device_ok": "" if not t.device else ("yes" if w.get("device") == t.device else "no"),
                    "clock": clock or "", "skew_min": "" if skew is None else skew,
                    "informative": "" if not d else ("yes" if d.get("informative") else "no"),
                    "place": place or "", "expected_place": t.place or "",
                    "place_ok": "" if not t.place else ("yes" if place == t.place else "no"),
                    "basis": "; ".join(w.get("basis") or []),
                })
    summary = {
        "tests": len(tests),
        "found": len({r["tag"] for r in rows if r.get("copy") != "NOT FOUND"}),
        "offset_ok": dict(Counter(r.get("offset_ok") or "n/a" for r in rows)),
        "device_ok": dict(Counter(r.get("device_ok") or "n/a" for r in rows)),
        "place_ok": dict(Counter(r.get("place_ok") or "n/a" for r in rows)),
        "utc_by_client": dict(Counter(f"{r['client']} ({r['copy']})" for r in rows if r.get("offset_ok") == "UTC")),
    }
    return rows, summary


def write_csv(rows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
