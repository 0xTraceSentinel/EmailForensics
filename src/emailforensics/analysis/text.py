from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from html.parser import HTMLParser

from emailforensics.analysis.config import Settings

MONTHS = {
    "january": 1, "jan": 1, "janvier": 1, "janv": 1,
    "february": 2, "feb": 2, "février": 2, "fevrier": 2, "févr": 2, "fevr": 2, "fév": 2,
    "march": 3, "mar": 3, "mars": 3,
    "april": 4, "apr": 4, "avril": 4, "avr": 4,
    "may": 5, "mai": 5,
    "june": 6, "jun": 6, "juin": 6,
    "july": 7, "jul": 7, "juillet": 7, "juil": 7,
    "august": 8, "aug": 8, "août": 8, "aout": 8,
    "september": 9, "sep": 9, "sept": 9, "septembre": 9,
    "october": 10, "oct": 10, "octobre": 10,
    "november": 11, "nov": 11, "novembre": 11,
    "december": 12, "dec": 12, "décembre": 12, "decembre": 12, "déc": 12,
}
_MONTH_RE = "|".join(sorted((re.escape(m) for m in MONTHS), key=len, reverse=True))

_BLOCK_TAGS = {"br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self.skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head"):
            self.skip = max(0, self.skip - 1)
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    p = _TextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:
        return re.sub(r"<[^>]+>", " ", html)
    text = "".join(p.parts).replace("\xa0", " ")
    return re.sub(r"\n[ \t]*\n(?:[ \t]*\n)+", "\n\n", text)


def message_text(body_text: str | None, body_html: str | None) -> str:
    if body_text and body_text.strip():
        return body_text.replace("\r\n", "\n")
    if body_html:
        return html_to_text(body_html)
    return ""


_SEPARATOR = re.compile(
    r"^\s*(?:-{2,}\s*(?:original message|message d'origine|forwarded message|message transf[ée]r[ée]|"
    r"weitergeleitete nachricht)\s*-{2,}|_{10,})\s*$",
    re.I,
)
_ON_WROTE = re.compile(r"^\s*(?:on|le)\s.{5,240}?(?:wrote|a écrit|a ecrit)\s*:\s*$", re.I)
_FROM_LINE = re.compile(r"^\s*\*?(?:from|de|von)\s*\*?\s*:", re.I)
_SENT_LINE = re.compile(r"^\s*\*?(sent|date|envoyé|envoye|gesendet|datum)\s*\*?\s*:\s*(.+)$", re.I)
_QUOTE_LINE = re.compile(r"^\s*>")


@dataclass
class Quoted:
    authored: str
    header_kind: str | None
    header_text: str | None
    sent_value: str | None


def split_quoted(text: str) -> Quoted:
    lines = text.split("\n")
    n = len(lines)
    for i, line in enumerate(lines):
        joined = line if i + 1 >= n else line + " " + lines[i + 1].strip()
        if _ON_WROTE.match(line):
            return Quoted("\n".join(lines[:i]).strip(), "on_wrote", line.strip(), line.strip())
        if _ON_WROTE.match(joined) and re.match(r"^\s*(?:on|le)\s", line, re.I):
            return Quoted("\n".join(lines[:i]).strip(), "on_wrote", joined.strip(), joined.strip())
        if _SEPARATOR.match(line) or _FROM_LINE.match(line):
            window = [l for l in lines[i : i + 10] if l.strip()]
            sent = next((m.group(2).strip() for l in window if (m := _SENT_LINE.match(l))), None)
            if _SEPARATOR.match(line) or sent is not None:
                return Quoted("\n".join(lines[:i]).strip(), "header", "\n".join(window).strip(), sent)
        if _QUOTE_LINE.match(line):
            return Quoted("\n".join(lines[:i]).strip(), "angle", None, None)
    return Quoted(text.strip(), None, None, None)


_TIME = re.compile(r"(?<!\d)(\d{1,2})\s*[:h]\s*(\d{2})(?::(\d{2}))?\s*(a\.?\s?m\.?|p\.?\s?m\.?)?(?![\d])", re.I)
_DMY_NAME = re.compile(rf"(?<!\d)(\d{{1,2}})(?:st|nd|rd|th|er)?\s+({_MONTH_RE})\.?,?\s+(\d{{4}})", re.I)
_MDY_NAME = re.compile(rf"\b({_MONTH_RE})\.?\s+(\d{{1,2}})(?:st|nd|rd|th)?,?\s+(\d{{4}})", re.I)
_YMD = re.compile(r"(?<!\d)(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?!\d)")
_NUMERIC = re.compile(r"(?<!\d)(\d{1,2})[-/.](\d{1,2})[-/.](\d{2,4})(?!\d)")


def _year(y: str) -> int:
    v = int(y)
    return v + 2000 if v < 100 else v


def _safe_date(y: int, m: int, d: int) -> date | None:
    try:
        return date(y, m, d)
    except ValueError:
        return None


def candidate_dates(s: str) -> list[tuple[date, int]]:
    out: list[tuple[date, int]] = []
    for m in _DMY_NAME.finditer(s):
        if (d := _safe_date(int(m.group(3)), MONTHS[m.group(2).lower()], int(m.group(1)))) is not None:
            out.append((d, m.end()))
    for m in _MDY_NAME.finditer(s):
        if (d := _safe_date(int(m.group(3)), MONTHS[m.group(1).lower()], int(m.group(2)))) is not None:
            out.append((d, m.end()))
    for m in _YMD.finditer(s):
        if (d := _safe_date(int(m.group(1)), int(m.group(2)), int(m.group(3)))) is not None:
            out.append((d, m.end()))
    for m in _NUMERIC.finditer(s):
        a, b, y = int(m.group(1)), int(m.group(2)), _year(m.group(3))
        for d in {_safe_date(y, b, a), _safe_date(y, a, b)}:
            if d is not None:
                out.append((d, m.end()))
    return out


def candidate_datetimes(s: str) -> list[datetime]:
    dates = candidate_dates(s)
    if not dates:
        return []
    out = []
    for d, end in dates:
        tm = _TIME.search(s, end) or _TIME.search(s)
        if tm is None:
            continue
        h, mi = int(tm.group(1)), int(tm.group(2))
        ampm = (tm.group(4) or "").lower().replace(".", "").replace(" ", "")
        if ampm == "pm" and h < 12:
            h += 12
        elif ampm == "am" and h == 12:
            h = 0
        if h > 23 or mi > 59:
            continue
        out.append(datetime(d.year, d.month, d.day, h, mi))
    return list(dict.fromkeys(out))


def infer_offset(local_candidates: list[datetime], reference_utc: datetime, max_residual_min: float) -> tuple[int, float] | None:
    ref = reference_utc.replace(tzinfo=None, second=0, microsecond=0)
    best: tuple[int, float] | None = None
    for local in local_candidates:
        diff = (local - ref).total_seconds() / 60
        offset = int(round(diff / 15.0) * 15)
        residual = abs(diff - offset)
        if abs(offset) > 14 * 60 or residual > max_residual_min:
            continue
        if best is None or residual < best[1]:
            best = (offset, residual)
    return best


_MOBILE = re.compile(
    r"(sent from my (iphone|ipad|samsung|galaxy|android|huawei|blackberry|mobile)|"
    r"sent from outlook for (ios|android)|get outlook for (ios|android)|envoyé de mon (iphone|ipad)|"
    r"sent from yahoo mail for iphone|sent from the all-new aol app)",
    re.I,
)


def mobile_signature(text: str) -> str | None:
    m = _MOBILE.search(text)
    return m.group(0) if m else None


def _phrase_regex(phrases: list[str]) -> re.Pattern | None:
    if not phrases:
        return None
    parts = {r"\s+".join(re.escape(w) for w in p.lower().split()) for p in phrases if p.strip()}
    if not parts:
        return None
    return re.compile(r"(?<!\w)(" + "|".join(sorted(parts, key=len, reverse=True)) + r")(?!\w)", re.I)


class PhraseMatcher:
    def __init__(self, phrases: dict[str, list[str]]) -> None:
        self.patterns = {k: r for k, v in phrases.items() if (r := _phrase_regex(v)) is not None}

    def match(self, text: str) -> dict[str, list[str]]:
        out = {}
        for cat, rx in self.patterns.items():
            hits = sorted({re.sub(r"\s+", " ", m.group(1).lower()) for m in rx.finditer(text)})
            if hits:
                out[cat] = hits
        return out


class PlaceMatcher:
    def __init__(self, settings: Settings) -> None:
        self.keyword = {}
        self.airport = {}
        self.phone = {}
        self.any = {}
        for code, p in settings.places.items():
            kw = _phrase_regex(p.keywords)
            if kw is not None:
                self.keyword[code] = kw
            if p.airports:
                self.airport[code] = re.compile(r"(?<![A-Za-z])(" + "|".join(map(re.escape, p.airports)) + r")(?![A-Za-z])")
            if p.phone_prefixes:
                self.phone[code] = re.compile("(" + "|".join(re.escape(x) for x in p.phone_prefixes) + r")[\s(]*\d")
            alts = [r"\s+".join(map(re.escape, k.split())) for k in p.keywords] + [re.escape(a) for a in p.airports]
            if alts:
                alt = "|".join(sorted(alts, key=len, reverse=True))
                self.any[code] = (
                    re.compile(
                        rf"\b(?:i am|i'm|im|we are|we're|currently|still|just landed|landed|arrived|i'm back|back|here)"
                        rf"\s+(?:in|at)\s+(?:the\s+)?(?:{alt})\b|\bje suis (?:à|a|en|au)\s+(?:{alt})\b",
                        re.I,
                    ),
                    re.compile(
                        rf"\b(?:flying|travelling|traveling|heading|leaving for|en route to|on my way to|off to|"
                        rf"boarding for|on the way to)\s+(?:back\s+)?(?:to\s+)?(?:{alt})\b",
                        re.I,
                    ),
                )
        self.airport_place = {a: code for code, p in settings.places.items() for a in p.airports}

    def mentions(self, text: str) -> dict[str, list[str]]:
        out: dict[str, set[str]] = {}
        for code, rx in self.keyword.items():
            for m in rx.finditer(text):
                out.setdefault(code, set()).add(m.group(1))
        for code, rx in self.airport.items():
            for m in rx.finditer(text):
                out.setdefault(code, set()).add(m.group(1))
        return {k: sorted(v) for k, v in out.items()}

    def phones(self, text: str) -> dict[str, int]:
        return {code: len(rx.findall(text)) for code, rx in self.phone.items() if rx.search(text)}

    def statements(self, text: str) -> list[tuple[str, str, str]]:
        out = []
        for code, (present, travel) in self.any.items():
            for m in present.finditer(text):
                out.append(("present", code, m.group(0)))
            for m in travel.finditer(text):
                out.append(("travelling_to", code, m.group(0)))
        return out


_TRAVEL = re.compile(
    r"\b(itinerary|e-?ticket|boarding pass|booking confirmation|flight confirmation|check-?in|"
    r"reservation (?:is )?confirmed|hotel reservation|booking reference|pnr|your trip|trip receipt|"
    r"air mauritius|south african airways|airlink|flysafair|emirates|kenya airways|qatar airways|"
    r"lift airline|cemair|uber|bolt|marriott|hilton|radisson|sun resorts|beachcomber|constance|lux\*)\b",
    re.I,
)
_RIDE = re.compile(r"\b(uber|bolt|taxify)\b.{0,80}\b(trip|ride|receipt)\b|\b(trip|ride) with (uber|bolt)\b", re.I | re.S)


def is_travel(subject: str, text: str) -> bool:
    return bool(_TRAVEL.search(subject or "")) or bool(_TRAVEL.search(text[:4000]))


def is_ride_receipt(subject: str, text: str) -> bool:
    return bool(_RIDE.search((subject or "") + "\n" + text[:3000]))


def routes(text: str, airports: dict[str, str]) -> list[tuple[str, str, int]]:
    out = []
    rx = re.compile(r"(?<![A-Za-z])([A-Z]{3})(?![A-Za-z])\s*(?:-|–|—|→|->|>|to|/)\s*([A-Z]{3})(?![A-Za-z])")
    for m in rx.finditer(text):
        a, b = m.group(1), m.group(2)
        if a in airports and b in airports and airports[a] != airports[b]:
            out.append((a, b, m.start()))
    return out


def dates_near(text: str, pos: int, low: date, high: date, span: int = 400) -> list[date]:
    window = text[max(0, pos - span) : pos + span]
    return sorted({d for d, _ in candidate_dates(window) if low <= d <= high})


def ooo_window(text: str, sent: datetime) -> tuple[date, date] | None:
    low = sent.date() - timedelta(days=1)
    high = sent.date() + timedelta(days=120)
    ds = sorted({d for d, _ in candidate_dates(text[:2000]) if low <= d <= high})
    if not ds:
        return None
    return sent.date(), ds[-1]


_OOO_SUBJECT = re.compile(r"^\s*(automatic reply|auto(?:matic)?[- ]?reply|out of (?:the )?office|r[ée]ponse automatique|absence)\b", re.I)


def is_ooo(subject: str | None) -> bool:
    return bool(subject and _OOO_SUBJECT.search(subject))


def excerpt(text: str, needle: str, width: int = 160) -> str:
    i = text.lower().find(needle.lower())
    if i < 0:
        return text[:width].strip()
    start = max(0, i - width // 2)
    return re.sub(r"\s+", " ", text[start : i + len(needle) + width // 2]).strip()


_BOILERPLATE = re.compile(
    r"(intended (?:solely |only )?(?:for|to be used by) (?:the )?(?:use of )?(?:the )?(?:named )?(?:addressee|recipient|individual)|"
    r"not the intended recipient|if you (?:have )?receive[d]? this (?:e-?mail|message|communication|transmission) in error|"
    r"(?:e-?mail|message|communication)(?: and any (?:attachments?|files))?(?: transmitted with it)? (?:is|are|may be|contains?) "
    r"(?:strictly )?(?:confidential|privileged)|confidentiality (?:notice|note|caution)|\bdisclaimer\b|"
    r"unauthori[sz]ed (?:use|review|disclosure|copying|dissemination)|please (?:notify|inform|advise) the sender|"
    r"(?:delete|destroy) (?:this|the) (?:e-?mail|message|original)|virus(?:es)?\b.{0,60}\b(?:check|scan|free)|"
    r"\bunsubscribe\b|privacy (?:policy|notice|statement)|you are receiving this|view (?:this email )?in (?:your )?browser|"
    r"registered (?:office|in england|company)|reg(?:istration)?\.? no\.?|vat (?:no|number)|"
    r"think before you print|please consider the environment)",
    re.I | re.S,
)


def strip_boilerplate(text: str) -> str:
    paras = re.split(r"\n\s*\n", text)
    kept = [p for p in paras if not _BOILERPLATE.search(p)]
    return "\n\n".join(kept).strip()
