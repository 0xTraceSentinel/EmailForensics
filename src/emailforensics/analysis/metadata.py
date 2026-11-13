from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from emailforensics.analysis.config import Settings

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

PSETID_APPOINTMENT = "00062002-0000-0000-c000-000000000046"
PSETID_MEETING = "6ed8da90-450b-101b-98da-00aa003f1305"
LID_LOCATION = 0x8208
LID_START = 0x820D
LID_END = 0x820E
LID_TZ_STRUCT = 0x8233
LID_TZ_DESCRIPTION = 0x8234
LID_TZ_START_DISPLAY = 0x825E
LID_TZ_END_DISPLAY = 0x825F
LID_ONLINE = 0x8240


def _filetime(value: int) -> datetime | None:
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


@dataclass
class ThreadIndex:
    start_utc: datetime
    guid: str
    replies: list[datetime]

    def json(self) -> dict:
        return {
            "start_utc": self.start_utc.isoformat(),
            "guid": self.guid,
            "depth": len(self.replies),
            "replies_utc": [r.isoformat() for r in self.replies],
        }


def decode_thread_index(data: bytes | None) -> ThreadIndex | None:
    if not data or len(data) < 22 or (len(data) - 22) % 5:
        return None
    head = int.from_bytes(data[0:6], "big") << 16
    start = _filetime(head)
    if start is None or not 1990 <= start.year <= 2100:
        return None
    g = data[6:22]
    guid = "{:08x}-{:04x}-{:04x}-{}-{}".format(
        struct.unpack_from("<I", g, 0)[0],
        struct.unpack_from("<H", g, 4)[0],
        struct.unpack_from("<H", g, 6)[0],
        g[8:10].hex(),
        g[10:16].hex(),
    )
    replies = []
    t = head
    for off in range(22, len(data), 5):
        word = int.from_bytes(data[off : off + 4], "big")
        code, delta = word >> 31, word & 0x7FFFFFFF
        t += delta << (23 if code else 18)
        dt = _filetime(t)
        if dt is None:
            return None
        replies.append(dt)
    return ThreadIndex(start, guid, replies)


def thread_index_from_header(value: str | None) -> bytes | None:
    if not value:
        return None
    import base64

    try:
        return base64.b64decode(re.sub(r"\s+", "", value), validate=True)
    except Exception:
        return None


_IP4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IP6 = re.compile(r"(?<![0-9a-fA-F:])((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?:%\w+)?)(?![0-9a-fA-F:])")

ORIGIN_HEADERS = (
    "x-originating-ip",
    "x-ms-exchange-organization-originalclientipaddress",
    "x-ms-exchange-crosstenant-originalclientip",
    "x-forwarded-for",
    "x-real-ip",
)


def _ips(text: str) -> list[str]:
    out = []
    for m in _IP4.finditer(text):
        try:
            out.append(str(ipaddress.ip_address(m.group(1))))
        except ValueError:
            pass
    for m in _IP6.finditer(text):
        try:
            out.append(str(ipaddress.ip_address(m.group(1).split("%")[0])))
        except ValueError:
            pass
    return list(dict.fromkeys(out))


def ip_scope(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_link_local:
        return "local"
    if a.is_private or a.is_reserved or a.is_unspecified:
        return "private"
    return "public"


def place_for_ip(ip: str, settings: Settings) -> str | None:
    a = ipaddress.ip_address(ip)
    for code, p in settings.places.items():
        for cidr in p.ip_ranges:
            try:
                if a in ipaddress.ip_network(cidr, strict=False):
                    return code
            except ValueError:
                continue
    return None


def client_ips(headers: list[dict], settings: Settings) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()

    def add(ip: str, source: str) -> None:
        if (ip, source) in seen:
            return
        seen.add((ip, source))
        out.append({"ip": ip, "source": source, "scope": ip_scope(ip), "place": place_for_ip(ip, settings)})

    received = [h["value"] for h in headers if h["name"].lower() == "received"]
    for h in headers:
        if h["name"].lower() in ORIGIN_HEADERS:
            for ip in _ips(h["value"]):
                add(ip, h["name"])
    if received:
        first_hop = received[-1]
        m = re.match(r"\s*from\s+(.*?)\s+by\s", first_hop, re.I | re.S)
        for ip in _ips(m.group(1) if m else first_hop):
            add(ip, "Received[first hop]")
    return out


def client_name(headers: list[dict]) -> str | None:
    for name in ("x-mailer", "user-agent", "x-mimeole", "x-ms-exchange-organization-authsource"):
        for h in headers:
            if h["name"].lower() == name and h["value"].strip():
                return h["value"].strip()[:200]
    return None


def header(headers: list[dict], name: str) -> str | None:
    low = name.lower()
    return next((h["value"] for h in headers if h["name"].lower() == low), None)


def named(props: dict | None, guid: str, lid: int) -> object:
    if not props:
        return None
    prefix = f"{{{guid}}}:0x{lid:04x}:".lower()
    for k, v in props.items():
        if k.lower().startswith(prefix):
            return v.get("value")
    return None


def tz_definition_key(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        data = bytes.fromhex(value)
    except ValueError:
        return None
    if len(data) >= 8:
        cch = struct.unpack_from("<H", data, 6)[0]
        raw = data[8 : 8 + 2 * cch]
        if cch and len(raw) == 2 * cch:
            try:
                return raw.decode("utf-16-le")
            except UnicodeDecodeError:
                pass
    m = re.search(rb"((?:[\x20-\x7e]\x00){4,})", data)
    return m.group(1).decode("utf-16-le") if m else None


def tz_struct_bias(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        data = bytes.fromhex(value)
    except ValueError:
        return None
    if len(data) < 4:
        return None
    return -struct.unpack_from("<i", data, 0)[0]


def _dt(v: object) -> datetime | None:
    if isinstance(v, str):
        try:
            d = datetime.fromisoformat(v)
        except ValueError:
            return None
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return None


@dataclass
class Appointment:
    start: datetime | None
    end: datetime | None
    location: str | None
    tz_name: str | None
    tz_bias: int | None
    online: bool


def appointment(message_class: str | None, props: dict | None, body: str) -> Appointment | None:
    mc = (message_class or "").lower()
    if not (mc.startswith("ipm.appointment") or mc.startswith("ipm.schedule.meeting")):
        return None
    start = _dt(named(props, PSETID_APPOINTMENT, LID_START))
    end = _dt(named(props, PSETID_APPOINTMENT, LID_END))
    location = named(props, PSETID_APPOINTMENT, LID_LOCATION)
    tz_name = (
        tz_definition_key(named(props, PSETID_APPOINTMENT, LID_TZ_START_DISPLAY))
        or named(props, PSETID_APPOINTMENT, LID_TZ_DESCRIPTION)
    )
    bias = tz_struct_bias(named(props, PSETID_APPOINTMENT, LID_TZ_STRUCT))
    online = bool(named(props, PSETID_APPOINTMENT, LID_ONLINE)) or bool(
        re.search(r"teams\.microsoft\.com/l/meetup-join|zoom\.us/j/|meet\.google\.com/", body or "", re.I)
    ) or bool(location and re.search(r"microsoft teams|zoom|google meet|skype", str(location), re.I))
    return Appointment(
        start, end, str(location) if location else None, str(tz_name) if tz_name else None, bias, online
    )
