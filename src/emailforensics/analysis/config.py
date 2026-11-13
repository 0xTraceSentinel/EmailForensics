from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

DEFAULT_PLACES: dict[str, dict] = {
    "ZA": {
        "label": "South Africa",
        "offsets": [120],
        "timezones": ["South Africa Standard Time", "Africa/Johannesburg", "Harare, Pretoria"],
        "keywords": [
            "South Africa", "Johannesburg", "Joburg", "Jozi", "JHB", "Sandton", "Rosebank", "Midrand",
            "Pretoria", "Centurion", "Cape Town", "Stellenbosch", "Durban", "Umhlanga", "Gqeberha",
            "Port Elizabeth", "Bloemfontein", "OR Tambo", "Lanseria", "Fourways", "Melrose Arch", "Waterfront",
        ],
        "airports": ["JNB", "CPT", "DUR", "PLZ", "ELS", "BFN", "HLA", "GRJ", "KIM"],
        "phone_prefixes": ["+27"],
        "ip_ranges": [],
        "entities": [],
    },
    "MU": {
        "label": "Mauritius",
        "offsets": [240],
        "timezones": ["Mauritius Standard Time", "Indian/Mauritius", "Port Louis"],
        "keywords": [
            "Mauritius", "Port Louis", "Ebene", "Ebène", "Cybercity", "Grand Baie", "Flic en Flac", "Curepipe",
            "Quatre Bornes", "Rose Hill", "Moka", "Tamarin", "Black River", "Belle Mare", "Mahebourg",
            "Le Morne", "Pamplemousses", "Bagatelle",
        ],
        "airports": ["MRU", "RRG"],
        "phone_prefixes": ["+230"],
        "ip_ranges": [],
        "entities": [],
    },
}

DEFAULT_PHRASES: dict[str, list[str]] = {
    "instruction": [
        "please sign", "please approve", "please execute", "please arrange", "please proceed", "go ahead",
        "proceed with", "you can proceed", "make it happen", "get it done", "action this", "sign and return",
        "tell the bank", "instruct the", "i have decided", "i've decided", "we have decided", "we've decided",
        "i have agreed", "i've agreed", "we have agreed", "we've agreed", "let's do", "let us do",
        "i want you to", "we need to do", "veuillez signer", "merci de signer",
    ],
    "approval": [
        "approved", "i approve", "we approve", "resolved that", "it was resolved", "the board approved",
        "approved as tabled", "board resolution", "written resolution", "no objection", "i consent", "we consent",
        "i agree to the resolution", "duly signed", "approuvé",
    ],
    "formality": [
        "formality", "rubber stamp", "rubber-stamp", "for the file", "for the record", "just needs to sign",
        "only needs to sign", "just need to sign", "tick the box", "tick-box", "backdate", "back-date",
        "back date", "pre-sign", "pre-signed", "signed in advance", "already agreed", "already decided",
        "already approved", "paper the", "date it as", "sign in mauritius", "signed in mauritius",
    ],
    "poem_awareness": [
        "poem", "place of effective management", "effective management", "tax residence", "tax resident",
        "tax residency", "mind and management", "central management and control", "substance requirements",
        "economic substance", "physically present", "must be held in mauritius", "hold the meeting in mauritius",
        "exit tax", "dual resident", "tie-breaker", "tie breaker",
    ],
    "tax_authority": ["sars", "cfc", "controlled foreign company", "mra", "tax audit", "verification letter"],
    "channel_shift": [
        "take this offline", "call me", "phone me", "give me a call", "whatsapp", "on signal",
        "don't email", "do not email", "not on email", "not in writing", "discuss in person", "face to face",
        "let's chat", "delete this email after", "delete this message after", "delete after reading",
    ],
    "deliberation": [
        "i disagree", "we disagree", "i have a concern", "my concern", "our concern", "concerned about",
        "not comfortable", "uncomfortable with", "please clarify", "can you explain", "before we approve",
        "before approving", "propose instead", "suggest we change", "should be amended", "i would amend",
        "i reject", "we reject", "cannot approve", "can't approve", "do not approve", "will not approve",
        "defer the", "postpone the", "push back", "i query", "we query",
    ],
    "privilege": [
        "privileged", "legal advice", "without prejudice", "attorney-client", "attorney client",
        "legal professional privilege", "counsel's opinion", "senior counsel", "opinion of counsel",
        "subject to privilege",
    ],
}

DEFAULT_SETTINGS = {
    "sendtime": {"min_days": 3, "tolerance_min": 45, "day_boundary_offset_min": 180, "baseline_weeks": 13,
                 "min_day_agreement": 0.6, "calibration_min_weeks": 5, "calibration_min_messages": 3,
                 "calibration_min_agreement": 0.8},
    "quoted_header": {"max_residual_min": 4},
    "anomaly": {"gap_min_weekly": 10},
    "privilege_domains": [],
    "excluded_folders": ["Junk Email", "Deleted Items/Junk", "Spam", "RSS Feeds", "Sync Issues"],
}


@dataclass
class Place:
    code: str
    label: str
    offsets: list[int]
    timezones: list[str]
    keywords: list[str]
    airports: list[str]
    phone_prefixes: list[str]
    ip_ranges: list[str]
    entities: list[str]


@dataclass
class Person:
    id: str
    name: str | None
    names: list[str]
    addresses: list[str]
    base: str | None
    role: str | None
    board: bool
    custodian: bool


@dataclass
class Decision:
    id: str
    title: str
    formal_date: date | None
    formal_place: str | None
    formal_country: str | None
    source: str | None
    terms: list[str]
    window_start: date | None
    window_end: date | None


@dataclass
class Settings:
    places: dict[str, Place]
    phrases: dict[str, list[str]]
    sendtime: dict
    quoted_header: dict
    anomaly: dict
    privilege_domains: list[str]
    excluded_folders: list[str]
    raw: dict = field(repr=False, default_factory=dict)

    def place_for_offset(self, minutes: int | None) -> str | None:
        if minutes is None:
            return None
        hits = [p.code for p in self.places.values() if minutes in p.offsets]
        return hits[0] if len(hits) == 1 else None

    def place_for_timezone(self, name: str | None) -> str | None:
        if not name:
            return None
        low = name.lower()
        for p in self.places.values():
            if any(tz.lower() in low for tz in p.timezones):
                return p.code
        return None

    def sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.raw, sort_keys=True, default=str).encode()).hexdigest()


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load_settings(path: Path | None) -> Settings:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) if path else {}
    data = data or {}
    places_raw = _merge(DEFAULT_PLACES, data.get("places") or {})
    phrases_raw = dict(DEFAULT_PHRASES)
    for k, v in (data.get("phrases") or {}).items():
        phrases_raw[k] = list(v)
    for k, v in (data.get("extra_phrases") or {}).items():
        phrases_raw[k] = phrases_raw.get(k, []) + list(v)
    settings_raw = _merge(DEFAULT_SETTINGS, {k: v for k, v in data.items() if k in DEFAULT_SETTINGS})
    places = {
        code.upper(): Place(
            code=code.upper(),
            label=p.get("label", code),
            offsets=[int(o) for o in p.get("offsets", [])],
            timezones=list(p.get("timezones", [])),
            keywords=list(p.get("keywords", [])),
            airports=[a.upper() for a in p.get("airports", [])],
            phone_prefixes=list(p.get("phone_prefixes", [])),
            ip_ranges=list(p.get("ip_ranges", [])),
            entities=list(p.get("entities", [])),
        )
        for code, p in places_raw.items()
    }
    raw = {"places": places_raw, "phrases": phrases_raw, **settings_raw}
    return Settings(
        places=places,
        phrases=phrases_raw,
        sendtime=settings_raw["sendtime"],
        quoted_header=settings_raw["quoted_header"],
        anomaly=settings_raw["anomaly"],
        privilege_domains=[d.lower() for d in settings_raw["privilege_domains"]],
        excluded_folders=list(settings_raw["excluded_folders"]),
        raw=raw,
    )


def _date(v) -> date | None:
    if v is None or v == "":
        return None
    if isinstance(v, date):
        return v
    return date.fromisoformat(str(v))


def load_people(path: Path) -> list[Person]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    rows = data.get("people", data) if isinstance(data, dict) else data
    custodian_id = data.get("custodian") if isinstance(data, dict) else None
    people = []
    seen: set[str] = set()
    for r in rows or []:
        pid = str(r["id"])
        if pid in seen:
            raise ValueError(f"duplicate person id {pid!r}")
        seen.add(pid)
        name = r.get("name")
        names = [str(n) for n in r.get("names", [])]
        if name and name not in names:
            names.insert(0, name)
        people.append(
            Person(
                id=pid,
                name=name,
                names=names,
                addresses=[str(a).strip().lower() for a in r.get("addresses", [])],
                base=str(r["base"]).upper() if r.get("base") else None,
                role=r.get("role"),
                board=bool(r.get("board", False)),
                custodian=bool(r.get("custodian", False)) or pid == custodian_id,
            )
        )
    return people


def load_decisions(path: Path) -> list[Decision]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    rows = data.get("decisions", []) if isinstance(data, dict) else data
    out = []
    seen: set[str] = set()
    for r in rows:
        did = str(r["id"])
        if did in seen:
            raise ValueError(f"duplicate decision id {did!r}")
        seen.add(did)
        search = r.get("search") or {}
        window = search.get("window") or [None, None]
        out.append(
            Decision(
                id=did,
                title=str(r["title"]),
                formal_date=_date(r.get("formal_date")),
                formal_place=r.get("formal_place"),
                formal_country=str(r["formal_country"]).upper() if r.get("formal_country") else None,
                source=r.get("source"),
                terms=[str(t) for t in search.get("terms", [])],
                window_start=_date(window[0]),
                window_end=_date(window[1]),
            )
        )
    return out
