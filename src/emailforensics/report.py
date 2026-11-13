from __future__ import annotations

import csv
import html
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from pathlib import Path

import psycopg

from emailforensics import __version__
from emailforensics.analysis.config import Settings
from emailforensics.case import Case
from emailforensics.hashing import sha256_file
from emailforensics.store import db

UNKNOWN = "unknown"


def esc(v) -> str:
    return html.escape("" if v is None else str(v))


def fmt_dt(v: datetime | None) -> str:
    return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M") if v else ""


def fmt_off(m: int | None) -> str:
    if m is None:
        return ""
    sign = "+" if m >= 0 else "-"
    return f"{sign}{abs(m) // 60:02d}{abs(m) % 60:02d}"


def hhmm(minutes: int | None) -> str:
    if minutes is None:
        return ""
    m = minutes % 1440
    return f"{m // 60:02d}:{m % 60:02d}"


@dataclass
class Row:
    msg_id: int
    decision_id: str
    reasons: list[str]
    at: datetime | None
    offset: int | None
    offset_method: str | None
    subject: str | None
    sender: str | None
    sender_person: str | None
    sender_base: str | None
    place: str | None
    place_method: str | None
    place_strength: str | None
    roles: list[str]
    phrases: dict
    questions: int
    authored_len: int
    excerpt: str
    folder: list[str] | None
    item_state: str | None
    item_path: str
    sha256: str
    source_file: str
    custodian_sent: bool
    thread_key: str | None
    attachments: list[str]
    message_class: str | None


def _counts(values) -> str:
    c = Counter(v or UNKNOWN for v in values)
    if not c:
        return "—"
    return " · ".join(f"{k} {n}" for k, n in sorted(c.items(), key=lambda kv: (kv[0] == UNKNOWN, -kv[1], kv[0])))


class ReportData:
    def __init__(self, conn: psycopg.Connection, case: Case) -> None:
        self.conn, self.case = conn, case
        run = conn.execute(
            "SELECT id, tool_version, started_at, finished_at, status, config, config_sha256, stats FROM analysis_run"
            " WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if run is None:
            raise RuntimeError("no completed analysis run; run `emailforensics analyze` first")
        self.run = dict(zip(("id", "tool_version", "started_at", "finished_at", "status", "config", "config_sha256", "stats"), run))
        self.people = {
            r[0]: dict(zip(("id", "name", "base", "role", "board", "custodian"), r))
            for r in conn.execute("SELECT id, name, base, role, board, custodian FROM person ORDER BY id")
        }
        self.addresses = defaultdict(list)
        for a, p in conn.execute("SELECT address, person_id FROM person_address ORDER BY address"):
            self.addresses[p].append(a)
        self.custodian = next((p for p in self.people.values() if p["custodian"]), None)
        self.decisions = [
            dict(zip(("id", "title", "formal_date", "formal_place", "formal_country", "source", "terms", "window_start", "window_end"), r))
            for r in conn.execute(
                "SELECT id, title, formal_date, formal_place, formal_country, source, terms, window_start, window_end FROM decision ORDER BY id"
            )
        ]
        self.places = self.run["config"].get("places", {})
        changed = conn.execute(
            "SELECT greatest((SELECT max(loaded_at) FROM person), (SELECT max(loaded_at) FROM decision))"
        ).fetchone()[0]
        self.stale = changed is not None and changed > self.run["started_at"]

    def base(self, person: str | None) -> str | None:
        return self.people.get(person, {}).get("base") if person else None

    def sources(self) -> list[dict]:
        return [
            dict(zip(("id", "path", "file_name", "format", "size", "sha256", "custodian", "ingested_at"), r))
            for r in self.conn.execute(
                "SELECT id, path, file_name, format, size_bytes, sha256, custodian, ingested_at FROM source_file ORDER BY id"
            )
        ]

    def rows(self, decision_id: str) -> list[Row]:
        out = []
        for r in self.conn.execute(
            "SELECT m.id, dm.reasons, coalesce(a.sent_utc, m.date_utc), a.offset_minutes, a.offset_method, m.subject,"
            " a.sender_address, a.sender_person, a.place, a.place_method, a.place_strength, a.roles, a.phrases,"
            " a.questions, coalesce(length(a.authored_text), 0), left(a.authored_text, 400), m.folder_path,"
            " m.item_state, m.item_path, m.sha256, s.file_name, a.custodian_sent, a.thread_key,"
            " coalesce((SELECT array_agg(coalesce(at.filename, at.mime_path) ORDER BY at.id) FROM attachment at WHERE at.msg_id = m.id), '{}'),"
            " m.message_class"
            " FROM decision_message dm JOIN message m ON m.id = dm.msg_id"
            " JOIN source_file s ON s.id = m.source_file_id"
            " LEFT JOIN message_analysis a ON a.msg_id = m.id"
            " WHERE dm.decision_id = %s ORDER BY coalesce(a.sent_utc, m.date_utc) NULLS LAST, m.id",
            (decision_id,),
        ):
            out.append(Row(
                msg_id=r[0], decision_id=decision_id, reasons=list(r[1]), at=r[2], offset=r[3], offset_method=r[4],
                subject=r[5], sender=r[6], sender_person=r[7], sender_base=self.base(r[7]), place=r[8], place_method=r[9],
                place_strength=r[10], roles=list(r[11] or []), phrases=r[12] or {}, questions=r[13] or 0, authored_len=r[14],
                excerpt=(r[15] or "").replace("\n", " "), folder=r[16], item_state=r[17], item_path=r[18], sha256=r[19],
                source_file=r[20], custodian_sent=bool(r[21]), thread_key=r[22], attachments=list(r[23]), message_class=r[24],
            ))
        return out

    def documents(self, decision_id: str) -> list[dict]:
        cols = ("sha256", "filename", "kind", "author", "last_modified_by", "company", "application", "template", "created",
                "created_offset", "modified", "modified_offset", "editors", "esign", "ips", "places", "first_seen", "messages")
        return [
            dict(zip(cols, r))
            for r in self.conn.execute(
                "SELECT am.sha256, min(a.filename), am.kind, am.author, am.last_modified_by, am.company, am.application,"
                " am.template, am.created, am.created_offset, am.modified, am.modified_offset, am.editors, am.esign, am.ips,"
                " am.places, min(m.date_utc), count(DISTINCT m.id)"
                " FROM decision_message dm JOIN attachment a ON a.msg_id = dm.msg_id JOIN attachment_meta am ON am.sha256 = a.sha256"
                " JOIN message m ON m.id = a.msg_id WHERE dm.decision_id = %s"
                " GROUP BY am.sha256 ORDER BY min(m.date_utc) NULLS LAST",
                (decision_id,),
            )
        ]

    def anomalies(self, decision_id: str | None = None) -> list[dict]:
        cols = ("kind", "decision_id", "msg_id", "sha256", "at_utc", "detail")
        q = "SELECT kind, decision_id, msg_id, sha256, at_utc, detail FROM anomaly"
        if decision_id is None:
            return [dict(zip(cols, r)) for r in self.conn.execute(q + " ORDER BY at_utc NULLS LAST, id")]
        return [dict(zip(cols, r)) for r in self.conn.execute(q + " WHERE decision_id = %s ORDER BY at_utc NULLS LAST, id", (decision_id,))]

    def evidence(self, person: str | None = None) -> list[dict]:
        cols = ("person_id", "msg_id", "method", "place", "start_utc", "end_utc", "strength", "detail")
        q = "SELECT person_id, msg_id, method, place, start_utc, end_utc, strength, detail FROM location_evidence"
        if person is None:
            return [dict(zip(cols, r)) for r in self.conn.execute(q + " ORDER BY start_utc, id")]
        return [dict(zip(cols, r)) for r in self.conn.execute(q + " WHERE person_id = %s ORDER BY start_utc, id", (person,))]

    def weeks(self, person: str) -> list[dict]:
        cols = ("week_start", "days", "messages", "median_first_min", "median_last_min", "shift_min", "place")
        return [dict(zip(cols, r)) for r in self.conn.execute(
            "SELECT week_start, days, messages, median_first_min, median_last_min, shift_min, place FROM sendtime_week"
            " WHERE person_id = %s ORDER BY week_start", (person,))]

    def reviews(self) -> list[dict]:
        cols = ("reason", "decision_id", "msg_id", "sha256", "detail", "subject", "item_path")
        return [dict(zip(cols, r)) for r in self.conn.execute(
            "SELECT r.reason, r.decision_id, r.msg_id, r.sha256, r.detail, m.subject, m.item_path FROM review_item r"
            " LEFT JOIN message m ON m.id = r.msg_id ORDER BY r.reason, r.decision_id NULLS LAST, r.id")]

    def coverage(self) -> dict:
        c = {}
        c["messages"], c["first"], c["last"] = self.conn.execute(
            "SELECT count(*), min(date_utc), max(date_utc) FROM message WHERE parent_id IS NULL").fetchone()
        c["custodian_sent"] = self.conn.execute("SELECT count(*) FROM message_analysis WHERE custodian_sent").fetchone()[0]
        c["sent_offsets"] = dict(self.conn.execute(
            "SELECT coalesce(offset_method, 'none'), count(*) FROM message_analysis WHERE custodian_sent GROUP BY 1").fetchall())
        c["sent_offset_values"] = dict(self.conn.execute(
            "SELECT coalesce(offset_minutes::text, 'none'), count(*) FROM message_analysis WHERE custodian_sent GROUP BY 1 ORDER BY 2 DESC").fetchall())
        c["sent_places"] = dict(self.conn.execute(
            "SELECT coalesce(place, 'unknown'), count(*) FROM message_analysis WHERE custodian_sent GROUP BY 1").fetchall())
        c["received_offsets"] = dict(self.conn.execute(
            "SELECT coalesce(m.date_offset_minutes::text, 'none'), count(*) FROM message m JOIN message_analysis a ON a.msg_id = m.id"
            " WHERE NOT a.custodian_sent AND m.parent_id IS NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 12").fetchall())
        c["evidence_methods"] = self.conn.execute(
            "SELECT method, coalesce(place, '?'), strength, count(*) FROM location_evidence GROUP BY 1, 2, 3 ORDER BY 1, 2").fetchall()
        c["attachments"] = self.conn.execute("SELECT count(DISTINCT sha256) FROM attachment").fetchone()[0]
        c["attachments_meta"] = self.conn.execute("SELECT count(*) FROM attachment_meta").fetchone()[0]
        c["esign"] = self.conn.execute("SELECT count(*) FROM attachment_meta WHERE esign IS NOT NULL").fetchone()[0]
        c["item_states"] = dict(self.conn.execute(
            "SELECT coalesce(item_state, 'n/a'), count(*) FROM message GROUP BY 1").fetchall())
        c["mobile_sent"] = self.conn.execute("SELECT count(*) FROM message_analysis WHERE custodian_sent AND mobile").fetchone()[0]
        return c


def verify_sources(sources: list[dict]) -> list[dict]:
    out = []
    for s in sources:
        p = Path(s["path"])
        if not p.exists():
            status = "missing"
        else:
            status = "verified" if sha256_file(p) == s["sha256"] else "CHANGED"
        out.append({**s, "status": status})
    return out


def indicator_matrix(data: ReportData, d: dict, rows: list[Row], docs: list[dict], anomalies: list[dict]) -> list[tuple[str, str, str]]:
    formal = datetime.combine(d["formal_date"], time(0), tzinfo=timezone.utc) if d["formal_date"] else None
    top = [r for r in rows if not r.item_path.count("/")]
    before = [r for r in top if formal and r.at and r.at < formal]
    instr = [r for r in top if "instruction" in r.roles]
    appr = [r for r in top if "approval" in r.roles]
    formal_c = d["formal_country"]
    cust_base = (data.custodian or {}).get("base")
    offshore_board = {
        pid for pid, p in data.people.items()
        if p["board"] and p["base"] and (p["base"] == formal_c if formal_c else p["base"] != cust_base)
    }
    deliberation = [r for r in top if r.sender_person in offshore_board and ("deliberation" in r.roles or r.questions) and r.authored_len > 120]
    board_msgs = [r for r in top if r.sender_person in offshore_board]
    starters: dict[str, Row] = {}
    for r in top:
        if r.thread_key and r.at and (r.thread_key not in starters or r.at < starters[r.thread_key].at):
            starters[r.thread_key] = r
    doc_places = [",".join(x["places"]) if x["places"] else None for x in docs]
    on_day = []
    if data.custodian and d["formal_date"]:
        lo = datetime.combine(d["formal_date"], time(0), tzinfo=timezone.utc)
        hi = lo + timedelta(days=1)
        on_day = [e for e in data.evidence(data.custodian["id"]) if e["start_utc"] < hi and e["end_utc"] >= lo]
    flags = Counter(role for r in top for role in r.roles if role in ("formality", "poem_awareness", "channel_shift", "privilege"))
    an = Counter(a["kind"] for a in anomalies)
    return [
        ("Messages before the formal date: sender's home base", _counts(r.sender_base for r in before),
         "Who was active before the formal approval; home base comes from the people register."),
        ("Messages before the formal date: sender's inferred location", _counts(r.place for r in before),
         "Location at time of sending, from offsets, presence evidence and send-time patterns (see strength per row)."),
        ("Instruction-type messages: sender's home base", _counts(r.sender_base for r in instr),
         "Phrase-based; every hit needs reading in context."),
        ("Instruction-type messages: sender's inferred location", _counts(r.place for r in instr), ""),
        ("Approval-type messages: sender's inferred location", _counts(r.place for r in appr), ""),
        ("Thread starters: home base", _counts(r.sender_base for r in starters.values()), "Who opened the conversations about this decision."),
        ("Offshore board members: messages / substantive input", f"{len(board_msgs)} / {len(deliberation)}",
         "Input = questions, pushback or amendments from board members based in the formal place, with more than a line of text."),
        ("Decision documents: place signals", _counts(doc_places) if docs else "no documents with metadata",
         "From author/company entities, PDF/Word time zone offsets and e-sign IP ranges you configured."),
        ("Custodian's location evidence on the formal date", _counts(f"{e['place']} ({e['method']}, {e['strength']})" for e in on_day) if on_day else "none found",
         "Where the custodian appears to have been on the day of the formal approval."),
        ("Language flags", ", ".join(f"{k} {v}" for k, v in sorted(flags.items())) or "none", "Formality, POEM-awareness, channel-shift and privilege phrases."),
        ("Anomalies", ", ".join(f"{k} {v}" for k, v in sorted(an.items())) or "none", "Missing thread ancestors, recovered items, document timing, location conflicts."),
    ]


CSS = """
:root{--bg:#fbfaf8;--fg:#1d1d1f;--muted:#6b6b70;--line:#e3e1dc;--card:#ffffff;--accent:#2f5f8a;--za:#b5542f;--mu:#2f7a5f;--warn:#9a6b00;--code:#f2f0ec}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#17181a;--fg:#e8e6e3;--muted:#9a9894;--line:#2e2f33;--card:#1f2023;--accent:#7fb0dc;--za:#e08a63;--mu:#6cc7a1;--warn:#e0b64f;--code:#26272b}}
:root[data-theme="dark"]{--bg:#17181a;--fg:#e8e6e3;--muted:#9a9894;--line:#2e2f33;--card:#1f2023;--accent:#7fb0dc;--za:#e08a63;--mu:#6cc7a1;--warn:#e0b64f;--code:#26272b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1280px;margin:0 auto;padding:24px 16px 80px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:40px 0 10px;padding-top:12px;border-top:1px solid var(--line)}
h3{font-size:15px;margin:22px 0 8px}p.lede{color:var(--muted);margin:0 0 16px}.note{color:var(--muted);font-size:13px}
.banner{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);padding:12px 14px;border-radius:6px;margin:16px 0}
nav{display:flex;flex-wrap:wrap;gap:6px 14px;margin:12px 0 4px}nav a{color:var(--accent);text-decoration:none}
.tw{overflow-x:auto;border:1px solid var(--line);border-radius:6px;background:var(--card);margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);font-weight:600;white-space:nowrap}tr:last-child td{border-bottom:0}
code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:12px}.pill{display:inline-block;padding:0 6px;border-radius:9px;background:var(--code);margin:1px 2px 1px 0;font-size:11.5px;white-space:nowrap}
.ZA{color:var(--za);font-weight:600}.MU{color:var(--mu);font-weight:600}.weak{opacity:.75}.strong{font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.stat{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:10px 12px}
.stat b{display:block;font-size:20px}.stat span{color:var(--muted);font-size:12px}svg text{fill:var(--muted);font-size:10px}
details summary{cursor:pointer;color:var(--accent)}
"""


def _place(p: str | None) -> str:
    return f'<span class="{esc(p)}">{esc(p)}</span>' if p else '<span class="note">unknown</span>'


def _table(headers: list[str], rows: list[list[str]], raw: bool = True) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return f'<div class="tw"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _sendtime_svg(weeks: list[dict], places: dict) -> str:
    usable = [w for w in weeks if w["shift_min"] is not None]
    if not usable:
        return '<p class="note">Not enough sent items for a weekly pattern.</p>'
    w_px, h_px, pad = max(600, 8 * len(usable)), 220, 34
    lo = min(w["median_first_min"] for w in usable) - 60
    hi = max(w["median_first_min"] for w in usable) + 60
    span = max(hi - lo, 1)
    step = (w_px - 2 * pad) / max(len(usable) - 1, 1)
    pts = []
    for i, w in enumerate(usable):
        x = pad + i * step
        y = h_px - pad - (w["median_first_min"] - lo) / span * (h_px - 2 * pad)
        cls = w["place"] or "none"
        colour = "var(--za)" if cls == "ZA" else "var(--mu)" if cls == "MU" else "var(--muted)"
        pts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{colour}"><title>{esc(w["week_start"])}: first send {hhmm(w["median_first_min"])} UTC, shift {w["shift_min"]} min, {esc(w["place"] or "no label")}</title></circle>')
    ticks = []
    for m in range((lo // 60) * 60, hi + 1, 60):
        if m < lo:
            continue
        y = h_px - pad - (m - lo) / span * (h_px - 2 * pad)
        ticks.append(f'<line x1="{pad}" x2="{w_px - pad}" y1="{y:.1f}" y2="{y:.1f}" stroke="var(--line)"/><text x="2" y="{y + 3:.1f}">{hhmm(m)}</text>')
    labels = f'<text x="{pad}" y="{h_px - 8}">{esc(usable[0]["week_start"])}</text><text x="{w_px - pad - 60}" y="{h_px - 8}">{esc(usable[-1]["week_start"])}</text>'
    return (f'<div class="tw"><svg viewBox="0 0 {w_px} {h_px}" width="100%" role="img" aria-label="Median first send time per week, UTC">'
            + "".join(ticks) + "".join(pts) + labels + "</svg></div>")


def _write_csv(path: Path, headers: list[str], rows: list[list]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in rows:
            w.writerow(["" if v is None else (json.dumps(v, default=str, ensure_ascii=False) if isinstance(v, (dict, list)) else v) for v in r])


REVIEW_HELP = {
    "privilege": "Possible legal privilege. Have the attorneys review before anyone else reads or relies on it.",
    "formality": "Wording suggesting the formal approval was a formality or pre-arranged. Read in context.",
    "poem_awareness": "Mentions tax residence/POEM/SARS on a decision thread. Read in context; may also be privileged.",
    "poem_awareness_any": "Mentions tax residence/POEM/SARS anywhere in the mailbox.",
    "channel_shift": "Conversation moved off email (call, WhatsApp). Those channels are not in this evidence.",
    "esign_audit_trail": "E-signature certificate found. Read signer IPs and timestamps; geolocate the IPs historically.",
    "geolocate_ip": "Public client IP with no configured range. Needs a historical IP-to-location lookup.",
    "location_conflict": "Signals disagree on where the sender was. Decide which one to trust.",
    "no_location_signal": "Decision message with no location signal at all.",
    "unmapped_sender": "Sender on a decision thread not in the people register. Identify them.",
    "verify_itinerary": "Booked travel. Confirm it was taken and by whom.",
    "verify_ride_receipt": "Ride receipt. Confirm the rider.",
    "recoverable_item": "Deleted item (Recoverable Items) on a decision thread.",
    "orphan_item": "Orphaned item recovered outside the folder tree.",
    "attachment_unreadable": "Attachment could not be parsed for metadata.",
}


def build_report(case: Case, settings: Settings, out: Path, verify: bool = True) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    csv_dir = out / "csv"
    with db.connect(case.dsn) as conn:
        data = ReportData(conn, case)
        sources = verify_sources(data.sources()) if verify else [{**s, "status": "not checked"} for s in data.sources()]
        cov = data.coverage()
        parts: list[str] = []
        now = datetime.now(timezone.utc)
        parts.append(f"<h1>POEM email evidence: {esc(case.name)}</h1>")
        parts.append(f'<p class="lede">Generated {fmt_dt(now)} UTC · emailforensics {esc(__version__)} · analysis run {data.run["id"]}'
                     f' · config sha256 <code>{esc(data.run["config_sha256"][:16])}</code></p>')
        parts.append('<div class="banner"><b>This report collects evidence; it does not decide POEM.</b> Location signals are '
                     'indicators of varying strength, phrase tags are leads to read, and the matrices are counts, not scores. '
                     'Every row traces to a source file, an item path and a hash. Conclusions need a tax adviser weighing all '
                     'decisions, all evidence and the applicable law.</div>')
        if data.stale:
            parts.append('<div class="banner"><b>Stale analysis.</b> The people or decision register was loaded after the '
                         'last analysis run, so decision links and locations below may be missing or out of date. '
                         'Run <code>emailforensics analyze</code> again.</div>')
        nav = ['<a href="#integrity">Integrity</a>', '<a href="#coverage">What this mailbox can show</a>',
               '<a href="#people">People</a>', '<a href="#location">Custodian location</a>']
        nav += [f'<a href="#d-{esc(d["id"])}">{esc(d["id"])}</a>' for d in data.decisions]
        nav += ['<a href="#anomalies">Anomalies</a>', '<a href="#review">Human review</a>', '<a href="#limits">Limitations</a>']
        parts.append("<nav>" + "".join(nav) + "</nav>")

        parts.append('<h2 id="integrity">Evidence integrity</h2>')
        parts.append(_table(["File", "Format", "Size", "SHA-256", "Custodian", "Check"],
                            [[esc(s["file_name"]), esc(s["format"]), f"{s['size']:,}", f'<code>{esc(s["sha256"])}</code>', esc(s["custodian"]),
                              ("<b>" + esc(s["status"]) + "</b>") if s["status"] != "verified" else esc(s["status"])] for s in sources]))
        _write_csv(csv_dir / "sources.csv", ["path", "format", "size", "sha256", "custodian", "status"],
                   [[s["path"], s["format"], s["size"], s["sha256"], s["custodian"], s["status"]] for s in sources])

        parts.append('<h2 id="coverage">What this mailbox can show</h2>')
        sent = cov["custodian_sent"] or 0
        with_offset = sum(v for k, v in cov["sent_offsets"].items() if k != "none")
        located = sum(v for k, v in cov["sent_places"].items() if k != "unknown")
        stats = [
            (f"{cov['messages']:,}", "top-level items"),
            (f"{fmt_dt(cov['first'])[:10]} → {fmt_dt(cov['last'])[:10]}", "date range (UTC)"),
            (f"{sent:,}", "items sent by the custodian"),
            (f"{(with_offset / sent * 100 if sent else 0):.0f}%", "of sent items with any time zone offset"),
            (f"{(located / sent * 100 if sent else 0):.0f}%", "of sent items with a location signal"),
            (f"{cov['mobile_sent']:,}", "sent from a mobile client"),
            (f"{cov['attachments_meta']:,}/{cov['attachments']:,}", "attachments with document metadata"),
            (f"{cov['esign']:,}", "e-signature audit trails"),
        ]
        parts.append('<div class="grid">' + "".join(f'<div class="stat"><b>{esc(a)}</b><span>{esc(b)}</span></div>' for a, b in stats) + "</div>")
        parts.append("<h3>Where the custodian's sent-item offsets came from</h3>")
        parts.append(_table(["Method", "Items"], [[esc(k), f"{v:,}"] for k, v in sorted(cov["sent_offsets"].items(), key=lambda kv: -kv[1])]))
        parts.append('<p class="note">date_header: the item kept its own Date header. date_header_copy: recovered from another copy '
                     'of the same Message-ID in the mailbox. quoted_header: inferred from the "Sent:" line the custodian\'s client wrote '
                     'when quoting the message being replied to. none: no offset available.</p>')
        parts.append("<h3>Offsets seen on the custodian's sent items (minutes from UTC)</h3>")
        parts.append(_table(["Offset", "Items"], [[esc(fmt_off(int(k)) if k != "none" else "none"), f"{v:,}"] for k, v in cov["sent_offset_values"].items()]))
        if with_offset and cov["sent_offset_values"].get("0", 0) > with_offset / 2:
            parts.append('<div class="banner">Most offsets on sent items are +0000. That usually means the Date header was written by '
                         'the mail server (common with Exchange Online), so it says nothing about the sender\'s location.</div>')
        parts.append("<h3>Offsets on received mail (other senders)</h3>")
        parts.append(_table(["Offset", "Items"], [[esc(fmt_off(int(k)) if k != "none" else "none"), f"{v:,}"] for k, v in cov["received_offsets"].items()]))
        parts.append("<h3>Location evidence collected</h3>")
        parts.append(_table(["Method", "Place", "Strength", "Count"], [[esc(a), _place(b if b != "?" else None), esc(c), f"{n:,}"] for a, b, c, n in cov["evidence_methods"]]))

        parts.append('<h2 id="people">People register</h2>')
        parts.append(_table(["ID", "Name", "Base", "Role", "Board", "Custodian", "Addresses"],
                            [[esc(p["id"]), esc(p["name"]), _place(p["base"]), esc(p["role"]), "yes" if p["board"] else "",
                              "yes" if p["custodian"] else "", "<br>".join(esc(a) for a in data.addresses[p["id"]])] for p in data.people.values()]))
        if not data.people:
            parts.append('<p class="note">No people register loaded. Run <code>emailforensics people</code>.</p>')

        parts.append('<h2 id="location">Custodian location</h2>')
        cust_id = data.custodian["id"] if data.custodian else "custodian"
        weeks = data.weeks(cust_id)
        parts.append("<h3>Send-time pattern (median first send per week, UTC)</h3>")
        parts.append('<p class="note">Office hours in Mauritius (UTC+4) start about two hours earlier in UTC than in South Africa (UTC+2). '
                     'Weeks whose first sends shift by that amount are labelled with the matching place. It is a weak, aggregate signal: '
                     'people keep home hours when travelling briefly.</p>')
        cal = (data.run["stats"] or {}).get(f"sendtime_{cust_id}_calibration")
        if cal:
            verdict = ("validated" if cal["reliable"] else "NOT validated, so it adds no location evidence")
            parts.append(f'<div class="banner"><b>Send-time pattern {esc(verdict)}.</b> Checked against the custodian&#39;s own '
                         f'Date-header offsets in {cal["weeks_checked"]} labelled weeks; the label matched the offsets in '
                         f'{esc(cal["agreement"] if cal["agreement"] is not None else "n/a")} of them '
                         f'({esc(", ".join(f"{k} {v}" for k, v in cal["label_vs_offsets"].items()) or "no overlap")}). '
                         'Weekly labels below are shown for reference only unless validated.</div>')
        parts.append(_sendtime_svg(weeks, data.places))
        parts.append("<details><summary>Weekly table</summary>" + _table(
            ["Week", "Days", "Sent", "Median first (UTC)", "Median last (UTC)", "Shift (min)", "Consistent with"],
            [[esc(w["week_start"]), str(w["days"]), str(w["messages"]), hhmm(w["median_first_min"]), hhmm(w["median_last_min"]),
              esc(w["shift_min"]), _place(w["place"]) if w["shift_min"] is not None else '<span class="note">too few days</span>'] for w in weeks]) + "</details>")
        _write_csv(csv_dir / "sendtime_weeks.csv", ["week_start", "days", "messages", "median_first_utc", "median_last_utc", "shift_min", "place"],
                   [[w["week_start"], w["days"], w["messages"], hhmm(w["median_first_min"]), hhmm(w["median_last_min"]), w["shift_min"], w["place"]] for w in weeks])
        ev = data.evidence(cust_id)
        parts.append("<h3>Presence evidence for the custodian</h3>")
        firm = [e for e in ev if e["method"] not in ("send_time_pattern",) and not e["method"].startswith("tz_")]
        parts.append(_table(["From (UTC)", "To (UTC)", "Place", "Method", "Strength", "Detail", "Msg"],
                            [[fmt_dt(e["start_utc"]), fmt_dt(e["end_utc"]), _place(e["place"]), esc(e["method"]), esc(e["strength"]),
                              esc(json.dumps(e["detail"], ensure_ascii=False, default=str)[:300]), esc(e["msg_id"])] for e in firm[:2000]]))
        if not firm:
            parts.append('<p class="note">No calendar, travel, receipt or self-statement evidence found for the custodian.</p>')
        tz_days = defaultdict(Counter)
        for e in ev:
            if e["method"].startswith("tz_"):
                tz_days[e["start_utc"].date()][e["place"]] += 1
        if tz_days:
            parts.append("<details><summary>Days with time-zone signals on the custodian's own messages</summary>" + _table(
                ["Day (UTC)", "Signals"], [[esc(dd), " · ".join(f"{_place(p)} {n}" for p, n in c.most_common())] for dd, c in sorted(tz_days.items())]) + "</details>")
        all_ev = data.evidence()
        _write_csv(csv_dir / "location_evidence.csv", ["person_id", "msg_id", "method", "place", "start_utc", "end_utc", "strength", "detail"],
                   [[e["person_id"], e["msg_id"], e["method"], e["place"], e["start_utc"], e["end_utc"], e["strength"], e["detail"]] for e in all_ev])

        for d in data.decisions:
            rows = data.rows(d["id"])
            docs = data.documents(d["id"])
            anomalies = data.anomalies(d["id"])
            parts.append(f'<h2 id="d-{esc(d["id"])}">{esc(d["id"])}: {esc(d["title"])}</h2>')
            parts.append(f'<p class="lede">Formal record: {esc(d["formal_date"])} · {esc(d["formal_place"])} {_place(d["formal_country"]) if d["formal_country"] else ""}'
                         f' · source: {esc(d["source"])} · search terms: {esc(", ".join(d["terms"]) or "none (window only)")}'
                         f' · window: {esc(d["window_start"])} → {esc(d["window_end"])} · {len(rows):,} linked items</p>')
            parts.append("<h3>Indicator matrix</h3>")
            parts.append(_table(["Indicator", "Counts", "How to read it"], [[esc(a), esc(b), f'<span class="note">{esc(c)}</span>'] for a, b, c in indicator_matrix(data, d, rows, docs, anomalies)]))
            parts.append("<h3>Timeline</h3>")
            formal = d["formal_date"]
            trows = []
            for r in rows:
                phase = ""
                if formal and r.at:
                    day = r.at.date()
                    phase = "before" if day < formal else "formal day" if day == formal else "after"
                roles = "".join(f'<span class="pill">{esc(x)}</span>' for x in r.roles)
                where = _place(r.place) + (f' <span class="note {esc(r.place_strength)}">{esc(r.place_method)}, {esc(r.place_strength)}</span>' if r.place else "")
                who = esc(r.sender_person or r.sender) + (f" ({_place(r.sender_base)})" if r.sender_base else "")
                trows.append([
                    fmt_dt(r.at), esc(fmt_off(r.offset)) + (f'<br><span class="note">{esc(r.offset_method)}</span>' if r.offset_method else ""),
                    esc(phase), who, where, roles, esc(r.subject) + (f'<br><span class="note">{esc(r.excerpt[:220])}</span>' if r.excerpt else ""),
                    "<br>".join(esc(a) for a in r.attachments[:6]),
                    f'<span class="mono">{esc(r.source_file)}:{esc(r.item_path)}<br>{esc(r.sha256[:16])}…</span>' + (f'<br><b>{esc(r.item_state)}</b>' if r.item_state and r.item_state != "live" else ""),
                ])
            parts.append(_table(["UTC", "Offset", "Phase", "Sender (base)", "Sender location", "Tags", "Subject / authored text", "Attachments", "Source"], trows))
            _write_csv(csv_dir / f"timeline_{d['id']}.csv",
                       ["utc", "offset", "offset_method", "sender", "sender_person", "sender_base", "place", "place_method", "place_strength",
                        "roles", "phrases", "subject", "folder", "item_state", "source_file", "item_path", "sha256", "msg_id", "link_reasons"],
                       [[fmt_dt(r.at), fmt_off(r.offset), r.offset_method, r.sender, r.sender_person, r.sender_base, r.place, r.place_method,
                         r.place_strength, ";".join(r.roles), r.phrases, r.subject, "/".join(r.folder or []), r.item_state, r.source_file,
                         r.item_path, r.sha256, r.msg_id, ";".join(r.reasons)] for r in rows])
            parts.append("<h3>Documents</h3>")
            if docs:
                parts.append(_table(["First seen", "File", "Author / last modified by", "Company / app", "Created", "Modified", "Editors", "Places", "E-sign"],
                                    [[fmt_dt(x["first_seen"]), esc(x["filename"]) + f'<br><span class="mono note">{esc(x["sha256"][:16])}…</span>',
                                      esc(x["author"]) + "<br>" + esc(x["last_modified_by"]), esc(x["company"]) + "<br>" + esc(x["application"]),
                                      fmt_dt(x["created"]) + (f" ({fmt_off(x['created_offset'])})" if x["created_offset"] is not None else ""),
                                      fmt_dt(x["modified"]) + (f" ({fmt_off(x['modified_offset'])})" if x["modified_offset"] is not None else ""),
                                      "<br>".join(esc(f"{e['author']} ({e['type']} ×{e['count']}{', offsets ' + ','.join(fmt_off(o) for o in e['offsets']) if e['offsets'] else ''})") for e in (x["editors"] or [])[:8]),
                                      " ".join(_place(p) for p in x["places"]),
                                      esc(", ".join(x["esign"]["markers"])) + (f"<br>{len(x['ips'])} IPs" if x["ips"] else "") if x["esign"] else ""] for x in docs]))
            else:
                parts.append('<p class="note">No attachments with readable metadata on this decision.</p>')
            _write_csv(csv_dir / f"documents_{d['id']}.csv",
                       ["sha256", "filename", "kind", "author", "last_modified_by", "company", "application", "template", "created", "created_offset",
                        "modified", "modified_offset", "editors", "esign", "ips", "places", "first_seen", "messages"],
                       [[x[k] for k in ("sha256", "filename", "kind", "author", "last_modified_by", "company", "application", "template", "created",
                                        "created_offset", "modified", "modified_offset", "editors", "esign", "ips", "places", "first_seen", "messages")] for x in docs])
            if anomalies:
                parts.append("<h3>Anomalies on this decision</h3>")
                parts.append(_table(["When (UTC)", "Kind", "Detail", "Msg"], [[fmt_dt(a["at_utc"]), esc(a["kind"]), esc(json.dumps(a["detail"], ensure_ascii=False, default=str)[:400]), esc(a["msg_id"])] for a in anomalies]))

        parts.append('<h2 id="anomalies">All anomalies</h2>')
        all_an = data.anomalies()
        parts.append(_table(["Kind", "Count"], [[esc(k), str(v)] for k, v in Counter(a["kind"] for a in all_an).most_common()]))
        _write_csv(csv_dir / "anomalies.csv", ["kind", "decision_id", "msg_id", "sha256", "at_utc", "detail"],
                   [[a["kind"], a["decision_id"], a["msg_id"], a["sha256"], a["at_utc"], a["detail"]] for a in all_an])

        parts.append('<h2 id="review">Human review queue</h2>')
        reviews = data.reviews()
        parts.append('<p class="note">Everything the tool could not decide on its own. The full list is in <code>csv/review_queue.csv</code>.</p>')
        parts.append(_table(["Reason", "Items", "What a person needs to do"],
                            [[esc(k), str(v), esc(REVIEW_HELP.get(k, ""))] for k, v in Counter(r["reason"] for r in reviews).most_common()]))
        _write_csv(csv_dir / "review_queue.csv", ["reason", "decision_id", "msg_id", "item_path", "subject", "sha256", "detail", "what_to_do", "reviewer", "outcome"],
                   [[r["reason"], r["decision_id"], r["msg_id"], r["item_path"], r["subject"], r["sha256"], r["detail"], REVIEW_HELP.get(r["reason"], ""), "", ""] for r in reviews])

        parts.append('<h2 id="limits">Limitations of this evidence</h2>')
        parts.append("<ul>" + "".join(f"<li>{x}</li>" for x in LIMITATIONS) + "</ul>")
        parts.append(f'<p class="note">Analysis statistics: <code>{esc(json.dumps(data.run["stats"], default=str))}</code></p>')

    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>POEM Evidence Report</title><style>{CSS}</style></head><body><main>{''.join(parts)}</main></body></html>")
    index = out / "index.html"
    index.write_text(page, encoding="utf-8")
    return index, data.stale


LIMITATIONS = [
    "One mailbox shows one person's view. Other directors' mailboxes, the company secretary's files, calls, meetings, WhatsApp and Teams chats are not in it. Absence of evidence here is not evidence of absence.",
    "Time zone offsets reflect a device or client setting, not a location. Laptops often keep their home zone when travelling; servers often write +0000.",
    "Sent items in a PST usually have no Date header. Offsets for them are recovered only where another copy or a quoted reply header exists.",
    "Server IP addresses in Received headers (Microsoft, Google) describe the provider's infrastructure, not the sender. A tenant hosted in South African data centres can make every message look South African.",
    "Send-time patterns are aggregate and weak. Two hours is a small shift; short trips usually do not show.",
    "Phrase tags (instruction, approval, formality) are leads. Sarcasm, quoting and context defeat keyword matching; every tagged message needs reading.",
    "Presence evidence (itineraries, receipts, out-of-office notes) shows plans or bookings; whether the trip happened and who travelled needs confirming.",
    "Document metadata can be inherited from templates and copied files. An author name is the name on the machine that created the file, not necessarily the drafter.",
    "Privileged material may be present. Privilege review has to happen before analysis is relied on or shared.",
    "POEM is a legal judgment across all key decisions over a period, applying SARS Interpretation Note 6, case law and the SA–Mauritius treaty. This report does not make that judgment.",
]


def print_timeline(case: Case, decision_id: str) -> None:
    from rich.console import Console
    from rich.table import Table

    with db.connect(case.dsn) as conn:
        data = ReportData(conn, case)
        d = next((x for x in data.decisions if x["id"] == decision_id), None)
        if d is None:
            raise KeyError(decision_id)
        rows = data.rows(decision_id)
        if data.stale:
            Console(stderr=True).print("warning: registers changed since the last analysis; run `emailforensics analyze` again")
    t = Table(title=f"{d['id']}: {d['title']} (formal {d['formal_date']}, {d['formal_place'] or ''})", show_lines=False)
    for col in ("UTC", "Off", "Sender", "Base", "Location", "Tags", "Subject"):
        t.add_column(col, overflow="fold")
    for r in rows:
        t.add_row(fmt_dt(r.at), fmt_off(r.offset), r.sender_person or r.sender or "", r.sender_base or "",
                  f"{r.place or '?'} ({r.place_method or '-'}, {r.place_strength or '-'})" if r.place else "?",
                  ",".join(r.roles), (r.subject or "")[:80])
    Console().print(t)
