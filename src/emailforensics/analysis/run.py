from __future__ import annotations

import re
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone

import psycopg
from psycopg.types.json import Jsonb

from emailforensics import __version__
from emailforensics.analysis import docmeta, metadata, sendtime, text
from emailforensics.analysis.config import Decision, Person, Settings
from emailforensics.case import Case
from emailforensics.store import db

PAGE = 1000
SENT_FOLDERS = re.compile(r"^(sent items|sent mail|sent|éléments envoyés|elements envoyes|messages envoyés|gesendete elemente)$", re.I)
DRAFT_FOLDERS = re.compile(r"^(drafts|brouillons|entwürfe)$", re.I)
DOC_NAMES = re.compile(r"minute|resolution|r[ée]solution|board|consent|proc[eè]s[- ]verbal|pv\b|written|agreement|term ?sheet|spa\b", re.I)

STRENGTH_RANK = {"strong": 3, "moderate": 2, "weak": 1}


def _day_bounds(d: date) -> tuple[datetime, datetime]:
    start = datetime.combine(d, time(0), tzinfo=timezone.utc)
    return start, start + timedelta(days=1)


@dataclass
class Lite:
    id: int
    parent_id: int | None
    custodian: str | None
    folder_path: list[str] | None
    item_state: str | None
    message_class: str | None
    rfc_message_id: str | None
    in_reply_to: str | None
    refs: list[str]
    subject: str | None
    from_addr: list[dict]
    sender_addr: list[dict]
    to_addrs: list[dict]
    cc_addrs: list[dict]
    date_utc: datetime | None
    date_offset: int | None
    client_submit: datetime | None
    creation_time: datetime | None
    conversation_index: bytes | None
    sha256: str
    item_path: str


@dataclass
class Result:
    msg_id: int
    thread_key: str | None = None
    sender_address: str | None = None
    sender_person: str | None = None
    custodian_sent: bool = False
    sent_utc: datetime | None = None
    authored_text: str | None = None
    roles: list[str] = field(default_factory=list)
    phrases: dict = field(default_factory=dict)
    questions: int = 0
    client: str | None = None
    mobile: bool = False
    client_ips: list[dict] = field(default_factory=list)
    offset_minutes: int | None = None
    offset_method: str | None = None
    offset_detail: dict | None = None
    place: str | None = None
    place_method: str | None = None
    place_strength: str | None = None
    thread_index: dict | None = None
    quoted_sent: str | None = None


@dataclass
class Evidence:
    person_id: str | None
    msg_id: int | None
    method: str
    place: str | None
    start_utc: datetime
    end_utc: datetime
    strength: str
    detail: dict


class Analyzer:
    def __init__(self, conn: psycopg.Connection, case: Case, settings: Settings, log: Callable[[str], None]) -> None:
        self.conn, self.case, self.settings, self.log = conn, case, settings, log
        self.people: dict[str, Person] = {}
        self.by_address: dict[str, str] = {}
        self.by_name: dict[str, str] = {}
        self.decisions: list[Decision] = []
        self.lite: dict[int, Lite] = {}
        self.results: dict[int, Result] = {}
        self.evidence: list[Evidence] = []
        self.anomalies: list[dict] = []
        self.reviews: list[dict] = []
        self.phrases = text.PhraseMatcher(settings.phrases)
        self.places = text.PlaceMatcher(settings)
        self.custodian: Person | None = None
        self.weeks: dict[str, list[sendtime.Week]] = {}
        self.stats: Counter = Counter()
        self.quoted_jobs: list[int] = []
        self.sent_times: dict[str, list[datetime]] = {}
        self.doc_terms: dict[str, set[str]] = defaultdict(set)
        self.decision_msgs: dict[str, dict[int, set[str]]] = {}
        self.run_id = 0
        self.term_hits: dict[int, set[str]] = defaultdict(set)
        self.sendtime_calibration: dict[str, dict] = {}
        self.term_patterns: dict[str, re.Pattern] = {}

    def load_registers(self) -> None:
        for pid, name, names, base, role, board, custodian in self.conn.execute(
            "SELECT id, name, names, base, role, board, custodian FROM person"
        ):
            self.people[pid] = Person(pid, name, list(names), [], base, role, board, custodian)
            for n in names:
                self.by_name.setdefault(n.strip().lower(), pid)
        for addr, pid in self.conn.execute("SELECT address, person_id FROM person_address"):
            self.by_address[addr.lower()] = pid
            self.people[pid].addresses.append(addr)
        self.custodian = next((p for p in self.people.values() if p.custodian), None)
        for row in self.conn.execute(
            "SELECT id, title, formal_date, formal_place, formal_country, source, terms, window_start, window_end"
            " FROM decision ORDER BY id"
        ):
            self.decisions.append(Decision(*row[:6], list(row[6]), row[7], row[8]))
        for d in self.decisions:
            terms = [r"\s+".join(map(re.escape, t.split())) for t in d.terms if t.strip()]
            if terms:
                self.term_patterns[d.id] = re.compile(r"(?<!\w)(?:" + "|".join(terms) + r")(?!\w)", re.I)

    def person_for(self, addrs: list[dict]) -> tuple[str | None, str | None]:
        for a in addrs:
            address = (a.get("address") or "").strip().lower()
            if address and address in self.by_address:
                return address, self.by_address[address]
            name = (a.get("name") or "").strip().lower()
            if name and name in self.by_name:
                return address or None, self.by_name[name]
        first = next((a for a in addrs if a.get("address") or a.get("name")), None)
        if first is None:
            return None, None
        return (first.get("address") or "").lower() or None, None

    def load_lite(self) -> None:
        rows = self.conn.execute(
            "SELECT m.id, m.parent_id, s.custodian, m.folder_path, m.item_state, m.message_class, m.rfc_message_id,"
            " m.in_reply_to, m.refs, m.subject, m.from_addr, m.sender_addr, m.to_addrs, m.cc_addrs, m.date_utc,"
            " m.date_offset_minutes, m.client_submit_time, m.creation_time, m.conversation_index, m.sha256,"
            " m.item_path"
            " FROM message m JOIN source_file s ON s.id = m.source_file_id ORDER BY m.id"
        )
        for r in rows:
            self.lite[r[0]] = Lite(*r[:8], list(r[8] or []), *r[9:])
        self.stats["messages"] = len(self.lite)
        self.log(f"loaded {len(self.lite):,} messages")

    def excluded(self, m: Lite) -> bool:
        folders = {f.lower() for f in (m.folder_path or [])}
        return any(x.lower() in folders for x in self.settings.excluded_folders)

    def build_threads(self) -> None:
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        for m in self.lite.values():
            node = f"m{m.id:012d}"
            find(node)
            keys = [k for k in [m.rfc_message_id, m.in_reply_to, *m.refs] if k]
            for k in keys:
                union(node, f"id:{k}")
            ti = metadata.decode_thread_index(m.conversation_index)
            if ti is not None:
                union(node, f"conv:{ti.guid}")
                self.results.setdefault(m.id, Result(m.id)).thread_index = ti.json()
        root_ids: dict[str, int] = {}
        for m in self.lite.values():
            r = find(f"m{m.id:012d}")
            root_ids.setdefault(r, m.id)
        for m in self.lite.values():
            res = self.results.setdefault(m.id, Result(m.id))
            res.thread_key = f"T{root_ids[find(f'm{m.id:012d}')]}"
        self.stats["threads"] = len(root_ids)

    def is_custodian_sent(self, m: Lite, person: str | None) -> bool:
        if m.parent_id is not None:
            return False
        folders = m.folder_path or []
        if any(DRAFT_FOLDERS.match(f) for f in folders):
            return False
        if self.custodian is not None and person == self.custodian.id:
            return True
        return bool(folders) and SENT_FOLDERS.match(folders[-1]) is not None

    def message_pass(self) -> None:
        last = 0
        done = 0
        quoted_jobs: list[int] = []
        while True:
            rows = self.conn.execute(
                "SELECT id, body_text, body_html, headers, mapi_props FROM message WHERE id > %s ORDER BY id LIMIT %s",
                (last, PAGE),
            ).fetchall()
            if not rows:
                break
            for mid, body_text, body_html, headers, props in rows:
                last = mid
                self._one(self.lite[mid], body_text, body_html, headers or [], props, quoted_jobs)
            done += len(rows)
            self.log(f"messages analysed: {done:,}/{len(self.lite):,}")
        self.quoted_jobs = quoted_jobs

    def _one(self, m: Lite, body_text, body_html, headers: list[dict], props: dict | None, quoted_jobs: list[int]) -> None:
        r = self.results.setdefault(m.id, Result(m.id))
        address, person = self.person_for(m.from_addr)
        r.sender_address, r.sender_person = address, person
        r.custodian_sent = self.is_custodian_sent(m, person)
        r.sent_utc = m.client_submit or m.date_utc
        if self.excluded(m):
            return
        full = text.message_text(body_text, body_html)
        hay = (m.subject or "") + "\n" + full
        for did, rx in self.term_patterns.items():
            if rx.search(hay):
                self.term_hits[m.id].add(did)
        q = text.split_quoted(full)
        authored = text.strip_boilerplate(q.authored)
        r.authored_text = authored[:20000]
        r.quoted_sent = q.sent_value
        if q.sent_value:
            quoted_jobs.append(m.id)
        scan = (m.subject or "") + "\n" + authored
        r.phrases = self.phrases.match(scan)
        r.roles = sorted(r.phrases)
        r.questions = len(re.findall(r"\?(?:\s|$)", authored))
        if self.settings.privilege_domains:
            parts = [a.get("address") or "" for a in m.from_addr + m.to_addrs + m.cc_addrs]
            if any(p.lower().endswith(d) for p in parts for d in self.settings.privilege_domains):
                r.roles = sorted(set(r.roles) | {"privilege"})
                r.phrases.setdefault("privilege", []).append("privilege domain")
        r.client = metadata.client_name(headers)
        mob = text.mobile_signature(authored[-600:] if authored else "")
        r.mobile = mob is not None or bool(r.client and re.search(r"iphone|ipad|android|ios|mobile", r.client, re.I))
        r.client_ips = metadata.client_ips(headers, self.settings) if headers else []
        if r.thread_index is None:
            raw = metadata.thread_index_from_header(metadata.header(headers, "Thread-Index"))
            ti = metadata.decode_thread_index(raw)
            if ti is not None:
                r.thread_index = ti.json()
        if m.date_offset is not None:
            r.offset_minutes = m.date_offset
            r.offset_method = "date_header"
            r.offset_detail = {"date_header_on": "this item"}
        who = person or (f"addr:{address}" if address else None)
        when = r.sent_utc
        if when is not None and who is not None:
            for kind, place, phrase in self.places.statements(authored):
                strength = "moderate" if kind == "present" else "weak"
                end = when + (timedelta(hours=12) if kind == "present" else timedelta(days=1))
                self.evidence.append(Evidence(who, m.id, f"statement_{kind}", place, when - timedelta(hours=12), end, strength, {"text": phrase}))
            for ip in r.client_ips:
                if ip["place"]:
                    self.evidence.append(Evidence(who, m.id, "client_ip_range", ip["place"], when, when, "moderate", ip))
        self._presence(m, r, full, props, who)

    def _presence(self, m: Lite, r: Result, full: str, props: dict | None, who: str | None) -> None:
        cust = self.custodian.id if self.custodian else (f"custodian:{m.custodian}" if m.custodian else None)
        appt = metadata.appointment(m.message_class, props, full)
        if appt is not None and appt.start is not None:
            end = appt.end or appt.start + timedelta(hours=1)
            loc_places = self.places.mentions(appt.location or "")
            if len(loc_places) == 1 and not appt.online and cust:
                place = next(iter(loc_places))
                self.evidence.append(Evidence(cust, m.id, "calendar_location", place, appt.start, end, "moderate",
                                              {"location": appt.location, "subject": m.subject, "organizer": r.sender_address}))
            tz_place = self.settings.place_for_timezone(appt.tz_name) or self.settings.place_for_offset(appt.tz_bias)
            if tz_place and who:
                self.evidence.append(Evidence(who, m.id, "calendar_timezone", tz_place, appt.start, end, "weak",
                                              {"timezone": appt.tz_name, "bias_offset": appt.tz_bias, "subject": m.subject,
                                               "note": "time zone of the organiser's calendar, not proof of presence"}))
            r.offset_detail = {**(r.offset_detail or {}), "appointment": {"start": appt.start.isoformat(), "location": appt.location,
                                                                          "timezone": appt.tz_name, "online": appt.online}}
        when = r.sent_utc or m.date_utc
        if when is None:
            return
        subject = m.subject or ""
        if text.is_ooo(subject) and who:
            mentions = self.places.mentions(full[:2000])
            window = text.ooo_window(full, when)
            if len(mentions) == 1 and window:
                start, end = _day_bounds(window[0])[0], _day_bounds(window[1])[1]
                place, words = next(iter(mentions.items()))
                self.evidence.append(Evidence(who, m.id, "out_of_office", place, start, end, "weak",
                                              {"subject": subject, "text": text.excerpt(full, words[0])}))
        if cust is None or m.parent_id is not None:
            return
        if text.is_ride_receipt(subject, full):
            mentions = self.places.mentions(full[:6000])
            if len(mentions) == 1:
                self.evidence.append(Evidence(cust, m.id, "ride_receipt", next(iter(mentions)), when - timedelta(hours=12), when + timedelta(hours=2),
                                              "moderate", {"subject": subject, "note": "confirm the rider is the custodian"}))
                self.reviews.append({"reason": "verify_ride_receipt", "msg_id": m.id, "detail": {"subject": subject}})
            return
        if text.is_travel(subject, full):
            low, high = when.date() - timedelta(days=2), when.date() + timedelta(days=365)
            found = False
            for a, b, pos in text.routes(full, self.places.airport_place):
                for d in text.dates_near(full, pos, low, high):
                    start, end = _day_bounds(d)
                    self.evidence.append(Evidence(cust, m.id, "itinerary", self.places.airport_place[b], start, end + timedelta(days=1), "weak",
                                                  {"route": f"{a}-{b}", "flight_date": d.isoformat(), "subject": subject,
                                                   "note": "booked travel; confirm it was flown and by whom"}))
                    found = True
            if found:
                self.reviews.append({"reason": "verify_itinerary", "msg_id": m.id, "detail": {"subject": subject}})

    def recover_offsets(self) -> None:
        by_mid: dict[str, list[Lite]] = defaultdict(list)
        for m in self.lite.values():
            if m.rfc_message_id:
                by_mid[m.rfc_message_id].append(m)
        recovered = 0
        for m in self.lite.values():
            r = self.results[m.id]
            if r.offset_minutes is not None or not m.rfc_message_id:
                continue
            copies = [c for c in by_mid[m.rfc_message_id] if c.id != m.id and c.date_offset is not None]
            offsets = sorted({c.date_offset for c in copies})
            if len(offsets) == 1:
                r.offset_minutes = offsets[0]
                r.offset_method = "date_header_copy"
                r.offset_detail = {**(r.offset_detail or {}), "copies": [c.id for c in copies], "copy_folders": [c.folder_path for c in copies]}
                recovered += 1
        self.stats["offsets_from_copies"] = recovered
        max_res = float(self.settings.quoted_header["max_residual_min"])
        quoted = 0
        for mid in self.quoted_jobs:
            m, r = self.lite[mid], self.results[mid]
            candidates = text.candidate_datetimes(r.quoted_sent or "")
            if not candidates:
                continue
            ref, ref_kind, ref_id = None, None, None
            if m.in_reply_to:
                parents = [p for p in by_mid.get(m.in_reply_to, []) if (p.client_submit or p.date_utc)]
                if parents:
                    p = parents[0]
                    ref, ref_kind, ref_id = p.client_submit or p.date_utc, "parent_in_mailbox", p.id
            if ref is None and r.thread_index and r.thread_index["depth"] >= 1:
                chain = [r.thread_index["start_utc"], *r.thread_index["replies_utc"]]
                ref, ref_kind = datetime.fromisoformat(chain[-2]), "thread_index"
            if ref is None:
                continue
            hit = text.infer_offset(candidates, ref, max_res if ref_kind == "parent_in_mailbox" else 2.0)
            if hit is None:
                continue
            offset, residual = hit
            detail = {"quoted_sent": r.quoted_sent, "reference": ref_kind, "reference_msg_id": ref_id,
                      "reference_utc": ref.isoformat(), "residual_min": round(residual, 1),
                      "note": "display time zone of the replier's mail client when replying"}
            r.offset_detail = {**(r.offset_detail or {}), "quoted_header": {"offset": offset, **detail}}
            if r.offset_minutes is None:
                r.offset_minutes = offset
                r.offset_method = "quoted_header" if ref_kind == "parent_in_mailbox" else "quoted_header_thread_index"
            quoted += 1
        self.stats["offsets_from_quoted_headers"] = quoted

    def offset_evidence(self) -> None:
        for m in self.lite.values():
            r = self.results[m.id]
            who = r.sender_person or (f"addr:{r.sender_address}" if r.sender_address else None)
            when = r.sent_utc
            if who is None or when is None:
                continue
            candidates = []
            if r.offset_minutes is not None:
                candidates.append((r.offset_method, r.offset_minutes))
            qh = (r.offset_detail or {}).get("quoted_header")
            if qh and r.offset_method not in ("quoted_header", "quoted_header_thread_index"):
                candidates.append(("quoted_header", qh["offset"]))
            for method, off in candidates:
                place = self.settings.place_for_offset(off)
                if place is None:
                    continue
                strength = "moderate" if (r.mobile and method.startswith("date_header")) else "weak"
                self.evidence.append(Evidence(who, m.id, f"tz_{method}", place, when, when, strength,
                                              {"offset_minutes": off, "client": r.client, "mobile": r.mobile}))

    def send_patterns(self) -> None:
        by_person: dict[str, dict[str, datetime]] = defaultdict(dict)
        for m in self.lite.values():
            r = self.results[m.id]
            if not r.sent_utc or m.parent_id is not None:
                continue
            who = "custodian" if r.custodian_sent else None
            if r.custodian_sent and self.custodian:
                who = self.custodian.id
            elif r.sender_person and r.sender_person in self.people:
                who = r.sender_person
            if who is None:
                continue
            key = m.rfc_message_id or f"id:{m.id}"
            by_person[who].setdefault(key, r.sent_utc)
        self.sent_times = {k: sorted(v.values()) for k, v in by_person.items()}
        own_offsets: dict[str, list[tuple[datetime, str]]] = defaultdict(list)
        for m in self.lite.values():
            r = self.results[m.id]
            if r.offset_method == "date_header" and r.sent_utc and m.parent_id is None:
                place = self.settings.place_for_offset(r.offset_minutes)
                who = self.custodian.id if (r.custodian_sent and self.custodian) else r.sender_person
                if place and who:
                    own_offsets[who].append((r.sent_utc, place))
        self.sendtime_calibration = {}
        for who, times in self.sent_times.items():
            base = self.people[who].base if who in self.people else None
            weeks = sendtime.weekly(times, self.settings, base)
            self.weeks[who] = weeks
            cal = sendtime.calibrate(weeks, own_offsets.get(who, []), self.settings)
            self.sendtime_calibration[who] = cal
            self.stats[f"sendtime_{who}_calibration"] = cal
            if not cal["reliable"]:
                continue
            for w in weeks:
                if w.place and w.place != base:
                    start = datetime.combine(w.week_start, time(0), tzinfo=timezone.utc)
                    self.evidence.append(Evidence(who, None, "send_time_pattern", w.place, start, start + timedelta(days=7), "weak",
                                                  {"median_first_utc_min": w.median_first_min, "baseline_min": w.baseline_min,
                                                   "shift_min": w.shift_min, "days": w.days, "day_agreement": w.agreement,
                                                   "calibration": cal,
                                                   "note": "aggregate weekly pattern; not used to place individual messages"}))

    def assign_places(self) -> None:
        points: dict[str, list[tuple[datetime, Evidence]]] = defaultdict(list)
        spans: dict[str, list[Evidence]] = defaultdict(list)
        for e in self.evidence:
            if not e.person_id or not e.place:
                continue
            if e.start_utc == e.end_utc:
                points[e.person_id].append((e.start_utc, e))
            else:
                spans[e.person_id].append(e)
        for v in points.values():
            v.sort(key=lambda x: x[0])
        keys = {k: [t for t, _ in v] for k, v in points.items()}
        near = timedelta(hours=6)
        for m in self.lite.values():
            r = self.results[m.id]
            who = r.sender_person or (f"addr:{r.sender_address}" if r.sender_address else None)
            when = r.sent_utc
            if who is None or when is None:
                continue
            own: list[tuple[str, str, str]] = []
            if r.offset_minutes is not None:
                place = self.settings.place_for_offset(r.offset_minutes)
                if place:
                    strength = "moderate" if (r.mobile and r.offset_method.startswith("date_header")) else "weak"
                    own.append((place, r.offset_method, strength))
            for ip in r.client_ips:
                if ip["place"]:
                    own.append((ip["place"], "client_ip_range", "moderate"))
            others: list[tuple[str, str, str]] = []
            if who in points:
                lo = bisect_left(keys[who], when - near)
                hi = bisect_right(keys[who], when + near)
                others += [(e.place, f"nearby_{e.method}", e.strength) for _, e in points[who][lo:hi] if e.msg_id != m.id]
            others += [(e.place, e.method if e.msg_id == m.id else f"nearby_{e.method}", e.strength) for e in spans.get(who, [])
                       if e.method != "send_time_pattern" and e.start_utc - near <= when <= e.end_utc + near]
            options = own + others
            if not options:
                continue
            best = max(options, key=lambda o: (STRENGTH_RANK[o[2]], o in own, o[1] != "send_time_pattern"))
            r.place, r.place_method, r.place_strength = best
            firm = {o[0] for o in options if STRENGTH_RANK[o[2]] >= 2}
            direct = {o[0] for o in own} | firm
            if (r.sender_person or r.custodian_sent) and (len(firm) > 1 or (len(direct) > 1 and m.parent_id is None)):
                self.anomalies.append({"kind": "location_conflict", "msg_id": m.id, "at_utc": when,
                                       "detail": {"person": who, "signals": [{"place": o[0], "method": o[1], "strength": o[2]} for o in options]}})
                self.reviews.append({"reason": "location_conflict", "msg_id": m.id, "detail": {"person": who}})

    def attachments(self) -> None:
        rows = self.conn.execute(
            "SELECT DISTINCT ON (sha256) sha256, filename, content_type, size_bytes FROM attachment ORDER BY sha256"
        ).fetchall()
        terms = {d.id: [t.lower() for t in d.terms] for d in self.decisions}
        inserted = 0
        for i, (sha, filename, ctype, size) in enumerate(rows, 1):
            if i % 500 == 0:
                self.log(f"attachments analysed: {i:,}/{len(rows):,}")
            path = self.case.blobs.path(sha)
            if not path.exists() or size > docmeta.MAX_DOC_BYTES:
                continue
            try:
                meta = docmeta.analyse(path.read_bytes(), filename, ctype)
            except Exception as e:
                self.reviews.append({"reason": "attachment_unreadable", "sha256": sha, "detail": {"filename": filename, "error": f"{type(e).__name__}: {e}"}})
                continue
            if meta is None:
                continue
            sample = (meta.text_sample or "").lower()
            for did, ts in terms.items():
                if any(t in sample for t in ts):
                    self.doc_terms[sha].add(did)
            places = set()
            for code, p in self.settings.places.items():
                hay = " ".join(x for x in (meta.company, meta.author, meta.last_modified_by, meta.template) if x).lower()
                if any(ent.lower() in hay for ent in p.entities):
                    places.add(code)
            for off in (meta.created_offset, meta.modified_offset):
                pl = self.settings.place_for_offset(off)
                if pl:
                    places.add(pl)
            for ed in meta.editors:
                for off in ed.get("offsets", []):
                    pl = self.settings.place_for_offset(off)
                    if pl:
                        places.add(pl)
                        pid = self.by_name.get(ed["author"].strip().lower())
                        if ed.get("last"):
                            try:
                                at = datetime.fromisoformat(ed["last"].replace("Z", "")).replace(tzinfo=timezone.utc)
                                self.evidence.append(Evidence(pid or f"author:{ed['author']}", None, "tz_document_revision", pl, at, at, "weak",
                                                              {"sha256": sha, "filename": filename, "offset_minutes": off}))
                            except ValueError:
                                pass
            for ip in meta.ips:
                ip["place"] = metadata.place_for_ip(ip["ip"], self.settings)
                if ip["place"]:
                    places.add(ip["place"])
            if meta.esign is not None:
                self.reviews.append({"reason": "esign_audit_trail", "sha256": sha,
                                     "detail": {"filename": filename, **meta.esign,
                                                "note": "read signer IPs and times from the certificate; geolocate historically"}})
            self.conn.execute(
                "INSERT INTO attachment_meta (sha256, run_id, kind, title, author, last_modified_by, company, application, template,"
                " created, created_offset, modified, modified_offset, editors, esign, ips, places, detail)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (sha, self.run_id, meta.kind, meta.title, meta.author, meta.last_modified_by, meta.company, meta.application,
                 meta.template, meta.created, meta.created_offset, meta.modified, meta.modified_offset, Jsonb(meta.editors),
                 Jsonb(meta.esign) if meta.esign is not None else None, Jsonb(meta.ips), sorted(places), Jsonb(meta.detail)),
            )
            inserted += 1
        self.stats["attachments_with_metadata"] = inserted

    def link_decisions(self) -> None:
        for d in self.decisions:
            found: dict[int, set[str]] = defaultdict(set)
            lo = datetime.combine(d.window_start, time(0), tzinfo=timezone.utc) if d.window_start else None
            hi = datetime.combine(d.window_end, time(0), tzinfo=timezone.utc) + timedelta(days=1) if d.window_end else None
            terms = [t.replace('"', " ").strip() for t in d.terms if t.strip()]
            if terms:
                query = " OR ".join(f'"{t}"' for t in terms)
                likes = [f"%{t}%" for t in terms]
                for (mid,) in self.conn.execute(
                    "SELECT m.id FROM message m WHERE (m.body_tsv @@ websearch_to_tsquery('simple', %s)"
                    " OR m.subject ILIKE ANY(%s)"
                    " OR EXISTS (SELECT 1 FROM attachment a WHERE a.msg_id = m.id AND a.filename ILIKE ANY(%s)))"
                    " AND (%s::timestamptz IS NULL OR m.date_utc >= %s) AND (%s::timestamptz IS NULL OR m.date_utc < %s)",
                    (query, likes, likes, lo, lo, hi, hi),
                ):
                    found[mid].add("term")
                for mid, ds in self.term_hits.items():
                    if d.id not in ds:
                        continue
                    m = self.lite[mid]
                    if (lo is None or (m.date_utc and m.date_utc >= lo)) and (hi is None or (m.date_utc and m.date_utc < hi)):
                        found[mid].add("term")
                shas = [s for s, ds in self.doc_terms.items() if d.id in ds]
                if shas:
                    for (mid,) in self.conn.execute("SELECT msg_id FROM attachment WHERE sha256 = ANY(%s)", (shas,)):
                        m = self.lite[mid]
                        if (lo is None or (m.date_utc and m.date_utc >= lo)) and (hi is None or (m.date_utc and m.date_utc < hi)):
                            found[mid].add("attachment_text")
            else:
                for m in self.lite.values():
                    if m.date_utc and (lo is None or m.date_utc >= lo) and (hi is None or m.date_utc < hi):
                        found[m.id].add("window_only")
            for mid in list(found):
                m = self.lite[mid]
                while m.parent_id is not None:
                    found[m.parent_id].add("contains_match")
                    m = self.lite[m.parent_id]
            threads = {self.results[mid].thread_key for mid in found}
            for m in self.lite.values():
                if m.id in found or self.results[m.id].thread_key not in threads:
                    continue
                if (lo is None or (m.date_utc and m.date_utc >= lo - timedelta(days=30))) and (hi is None or (m.date_utc and m.date_utc < hi + timedelta(days=30))):
                    found[m.id].add("thread")
            self.decision_msgs[d.id] = found
            for mid, reasons in found.items():
                self.conn.execute(
                    "INSERT INTO decision_message (decision_id, msg_id, reasons) VALUES (%s, %s, %s)",
                    (d.id, mid, sorted(reasons)),
                )
            self.stats[f"decision_{d.id}_messages"] = len(found)

    def find_anomalies(self) -> None:
        cust_weeks = self.weeks.get(self.custodian.id if self.custodian else "custodian", [])
        if cust_weeks:
            counts = {w.week_start: w.messages for w in cust_weeks}
            first, last = min(counts), max(counts)
            weeks = []
            d = first
            while d <= last:
                weeks.append(d)
                d += timedelta(days=7)
            threshold = self.settings.anomaly["gap_min_weekly"]
            for i, w in enumerate(weeks):
                if counts.get(w, 0):
                    continue
                around = [counts.get(x, 0) for x in weeks[max(0, i - 4) : i] + weeks[i + 1 : i + 5]]
                avg = sum(around) / len(around) if around else 0
                if avg >= threshold:
                    self.anomalies.append({"kind": "sent_volume_gap", "at_utc": datetime.combine(w, time(0), tzinfo=timezone.utc),
                                           "detail": {"week_start": w.isoformat(), "neighbour_weekly_average": round(avg, 1)}})
        present = {m.conversation_index for m in self.lite.values() if m.conversation_index}
        for d in self.decisions:
            msgs = self.decision_msgs.get(d.id, {})
            formal = datetime.combine(d.formal_date, time(0), tzinfo=timezone.utc) if d.formal_date else None
            reported: set[bytes] = set()
            docs_done: set[str] = set()
            unmapped: dict[str, dict] = {}
            for mid in msgs:
                ci = self.lite[mid].conversation_index
                ti = self.results[mid].thread_index
                if not ci or not ti:
                    continue
                chain = [ti["start_utc"], *ti["replies_utc"]]
                for k in range(ti["depth"]):
                    prefix = ci[: 22 + 5 * k]
                    if prefix in present or prefix in reported:
                        continue
                    reported.add(prefix)
                    self.anomalies.append({"kind": "thread_ancestor_missing", "decision_id": d.id, "msg_id": mid,
                                           "at_utc": datetime.fromisoformat(chain[k]),
                                           "detail": {"conversation": ti["guid"], "level": k, "ancestor_time_utc": chain[k],
                                                      "subject": self.lite[mid].subject,
                                                      "note": "an earlier message in this Outlook conversation is not in the mailbox"}})
            for mid in msgs:
                m, r = self.lite[mid], self.results[mid]
                if m.item_state in ("recoverable", "orphan"):
                    self.anomalies.append({"kind": f"{m.item_state}_item", "decision_id": d.id, "msg_id": mid, "at_utc": m.date_utc,
                                           "detail": {"folder": m.folder_path, "subject": m.subject}})
                    self.reviews.append({"reason": f"{m.item_state}_item", "decision_id": d.id, "msg_id": mid, "detail": {"subject": m.subject}})
                for (sha, filename) in self.conn.execute("SELECT sha256, filename FROM attachment WHERE msg_id = %s", (mid,)):
                    if not filename or not DOC_NAMES.search(filename) or sha in docs_done:
                        continue
                    docs_done.add(sha)
                    meta = self.conn.execute("SELECT created, modified, author, last_modified_by, company, places FROM attachment_meta WHERE sha256 = %s", (sha,)).fetchone()
                    if not meta or not formal or not meta[0]:
                        continue
                    created = meta[0]
                    days = (created - formal).total_seconds() / 86400
                    kind = "document_created_before_formal_date" if days < 0 else "document_created_after_formal_date"
                    self.anomalies.append({"kind": kind, "decision_id": d.id, "msg_id": mid, "sha256": sha, "at_utc": created,
                                           "detail": {"filename": filename, "days_from_formal_date": round(days, 2), "author": meta[2],
                                                      "last_modified_by": meta[3], "company": meta[4], "places": meta[5]}})
            for mid in msgs:
                r = self.results[mid]
                for reason in ("formality", "poem_awareness", "channel_shift"):
                    if reason in r.roles:
                        self.reviews.append({"reason": reason, "decision_id": d.id, "msg_id": mid, "detail": {"phrases": r.phrases.get(reason)}})
                if r.place is None and self.lite[mid].parent_id is None and (r.custodian_sent or r.sender_person):
                    self.reviews.append({"reason": "no_location_signal", "decision_id": d.id, "msg_id": mid, "detail": {"sender": r.sender_address}})
                if r.sender_person is None and r.sender_address:
                    u = unmapped.setdefault(r.sender_address, {"sender": r.sender_address, "messages": 0, "first_msg_id": mid})
                    u["messages"] += 1
                    u["first_msg_id"] = min(u["first_msg_id"], mid)
            for u in sorted(unmapped.values(), key=lambda u: -u["messages"]):
                self.reviews.append({"reason": "unmapped_sender", "decision_id": d.id, "msg_id": u["first_msg_id"], "detail": u})
        for mid, r in self.results.items():
            if "privilege" in r.roles:
                self.reviews.append({"reason": "privilege", "msg_id": mid, "detail": {"phrases": r.phrases.get("privilege")}})
            if "poem_awareness" in r.roles:
                self.reviews.append({"reason": "poem_awareness_any", "msg_id": mid, "detail": {"phrases": r.phrases.get("poem_awareness")}})
        ips: dict[str, dict] = {}
        for mid, r in self.results.items():
            if not (r.sender_person or r.custodian_sent):
                continue
            for ip in r.client_ips:
                if ip["scope"] == "public" and not ip["place"]:
                    e = ips.setdefault(ip["ip"], {"ip": ip["ip"], "sources": set(), "messages": 0, "first": None, "last": None, "senders": set()})
                    e["sources"].add(ip["source"])
                    e["messages"] += 1
                    t = r.sent_utc
                    if t:
                        e["first"] = min(e["first"] or t, t)
                        e["last"] = max(e["last"] or t, t)
                    if r.sender_address:
                        e["senders"].add(r.sender_address)
        for e in ips.values():
            self.reviews.append({"reason": "geolocate_ip", "detail": {
                "ip": e["ip"], "sources": sorted(e["sources"]), "messages": e["messages"],
                "first": e["first"].isoformat() if e["first"] else None, "last": e["last"].isoformat() if e["last"] else None,
                "senders": sorted(e["senders"])[:20],
                "note": "look up historical owner/geolocation; Microsoft/Google server IPs say nothing about the sender"}})

    def write(self) -> None:
        with self.conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO message_analysis (msg_id, run_id, thread_key, sender_address, sender_person, custodian_sent, sent_utc,"
                " authored_text, roles, phrases, questions, client, mobile, client_ips, offset_minutes, offset_method, offset_detail,"
                " place, place_method, place_strength, thread_index)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [
                    (r.msg_id, self.run_id, r.thread_key, r.sender_address, r.sender_person, r.custodian_sent, r.sent_utc,
                     r.authored_text, r.roles, Jsonb(r.phrases), r.questions, r.client, r.mobile, Jsonb(r.client_ips),
                     r.offset_minutes, r.offset_method, Jsonb(r.offset_detail) if r.offset_detail else None,
                     r.place, r.place_method, r.place_strength, Jsonb(r.thread_index) if r.thread_index else None)
                    for r in self.results.values()
                ],
            )
            cur.executemany(
                "INSERT INTO location_evidence (run_id, person_id, msg_id, method, place, start_utc, end_utc, strength, detail)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [(self.run_id, e.person_id, e.msg_id, e.method, e.place, e.start_utc, e.end_utc, e.strength, Jsonb(_json(e.detail)))
                 for e in self.evidence],
            )
            cur.executemany(
                "INSERT INTO sendtime_week (person_id, week_start, days, messages, median_first_min, median_last_min, shift_min, place)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                [(who, w.week_start, w.days, w.messages, w.median_first_min, w.median_last_min, w.shift_min, w.place)
                 for who, weeks in self.weeks.items() for w in weeks],
            )
            cur.executemany(
                "INSERT INTO anomaly (run_id, kind, decision_id, msg_id, sha256, at_utc, detail) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                [(self.run_id, a["kind"], a.get("decision_id"), a.get("msg_id"), a.get("sha256"), a.get("at_utc"), Jsonb(_json(a.get("detail", {}))))
                 for a in self.anomalies],
            )
            seen = set()
            rows = []
            for v in self.reviews:
                key = (v["reason"], v.get("decision_id"), v.get("msg_id"), v.get("sha256"), str(v.get("detail", {}).get("ip")))
                if key in seen:
                    continue
                seen.add(key)
                rows.append((self.run_id, v["reason"], v.get("decision_id"), v.get("msg_id"), v.get("sha256"), Jsonb(_json(v.get("detail", {})))))
            cur.executemany(
                "INSERT INTO review_item (run_id, reason, decision_id, msg_id, sha256, detail) VALUES (%s,%s,%s,%s,%s,%s)", rows
            )
        self.stats["location_evidence"] = len(self.evidence)
        self.stats["anomalies"] = len(self.anomalies)
        self.stats["review_items"] = len(rows)


def _json(v):
    if isinstance(v, str):
        return v.replace("\x00", "")
    if isinstance(v, dict):
        return {k: _json(x) for k, x in v.items()}
    if isinstance(v, (list, tuple, set)):
        return [_json(x) for x in v]
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v


ANALYSIS_TABLES = ("review_item", "anomaly", "sendtime_week", "decision_message", "attachment_meta", "location_evidence", "message_analysis")


def analyze_case(case: Case, settings: Settings, argv: list[str], log: Callable[[str], None] = lambda s: None) -> dict:
    with db.connect(case.dsn) as conn:
        db.migrate(conn)
        run_id = conn.execute(
            "INSERT INTO analysis_run (tool_version, argv, config, config_sha256) VALUES (%s, %s, %s, %s) RETURNING id",
            (__version__, Jsonb(argv), Jsonb(_json(settings.raw)), settings.sha256()),
        ).fetchone()[0]
        a = Analyzer(conn, case, settings, log)
        a.run_id = run_id
        try:
            with conn.transaction():
                for t in ANALYSIS_TABLES:
                    conn.execute(f"DELETE FROM {t}")
                a.load_registers()
                if a.custodian is None:
                    log("warning: no custodian in people register; sent items are identified by folder only")
                a.load_lite()
                a.build_threads()
                a.message_pass()
                a.recover_offsets()
                a.offset_evidence()
                a.send_patterns()
                a.assign_places()
                a.attachments()
                a.link_decisions()
                a.find_anomalies()
                log("writing results")
                a.write()
        except Exception as e:
            conn.execute("UPDATE analysis_run SET finished_at = now(), status = %s, stats = %s WHERE id = %s",
                         ("failed", Jsonb({"error": f"{type(e).__name__}: {e}"}), run_id))
            raise
        stats = dict(a.stats)
        conn.execute("UPDATE analysis_run SET finished_at = now(), status = 'completed', stats = %s WHERE id = %s", (Jsonb(stats), run_id))
        return {"run_id": run_id, **stats}
