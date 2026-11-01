from __future__ import annotations

import codecs
import struct
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from emailforensics.hashing import sha256_bytes
from emailforensics.ingest.parse import Attachment, MapiFields, ParsedMessage, clean, msgids, parse_message

PT_SHORT = 0x0002
PT_LONG = 0x0003
PT_FLOAT = 0x0004
PT_DOUBLE = 0x0005
PT_CURRENCY = 0x0006
PT_APPTIME = 0x0007
PT_ERROR = 0x000A
PT_BOOLEAN = 0x000B
PT_OBJECT = 0x000D
PT_LONGLONG = 0x0014
PT_STRING8 = 0x001E
PT_UNICODE = 0x001F
PT_SYSTIME = 0x0040
PT_CLSID = 0x0048
PT_BINARY = 0x0102
MV_FLAG = 0x1000

FIXED_SIZE = {
    PT_SHORT: 2,
    PT_LONG: 4,
    PT_FLOAT: 4,
    PT_DOUBLE: 8,
    PT_CURRENCY: 8,
    PT_APPTIME: 8,
    PT_ERROR: 4,
    PT_BOOLEAN: 1,
    PT_LONGLONG: 8,
    PT_SYSTIME: 8,
    PT_CLSID: 16,
}
VARIABLE = {PT_STRING8, PT_UNICODE, PT_BINARY}

PS_MAPI = "00020328-0000-0000-c000-000000000046"
PS_PUBLIC_STRINGS = "00020329-0000-0000-c000-000000000046"

PR_MESSAGE_CLASS = 0x001A
PR_SUBJECT = 0x0037
PR_CLIENT_SUBMIT_TIME = 0x0039
PR_SENT_REPRESENTING_NAME = 0x0042
PR_SENT_REPRESENTING_ADDRTYPE = 0x0064
PR_SENT_REPRESENTING_EMAIL_ADDRESS = 0x0065
PR_CONVERSATION_TOPIC = 0x0070
PR_CONVERSATION_INDEX = 0x0071
PR_TRANSPORT_MESSAGE_HEADERS = 0x007D
PR_SENDER_NAME = 0x0C1A
PR_SENDER_ADDRTYPE = 0x0C1E
PR_SENDER_EMAIL_ADDRESS = 0x0C1F
PR_RECIPIENT_TYPE = 0x0C15
PR_MESSAGE_DELIVERY_TIME = 0x0E06
PR_MESSAGE_FLAGS = 0x0E07
PR_BODY = 0x1000
PR_RTF_COMPRESSED = 0x1009
PR_HTML = 0x1013
PR_INTERNET_MESSAGE_ID = 0x1035
PR_INTERNET_REFERENCES = 0x1039
PR_IN_REPLY_TO_ID = 0x1042
PR_DISPLAY_NAME = 0x3001
PR_ADDRTYPE = 0x3002
PR_EMAIL_ADDRESS = 0x3003
PR_CREATION_TIME = 0x3007
PR_LAST_MODIFICATION_TIME = 0x3008
PR_ATTACH_DATA = 0x3701
PR_ATTACH_FILENAME = 0x3704
PR_ATTACH_METHOD = 0x3705
PR_ATTACH_LONG_FILENAME = 0x3707
PR_ATTACH_MIME_TAG = 0x370E
PR_ATTACH_CONTENT_ID = 0x3712
PR_ATTACH_FLAGS = 0x3714
PR_SMTP_ADDRESS = 0x39FE
PR_INTERNET_CPID = 0x3FDE
PR_MESSAGE_CODEPAGE = 0x3FFD
PR_LAST_MODIFIER_NAME = 0x3FFA
PR_SENDER_SMTP_ADDRESS = 0x5D01
PR_SENT_REPRESENTING_SMTP_ADDRESS = 0x5D02
PR_ATTACHMENT_HIDDEN = 0x7FFE

ATTACH_EMBEDDED_MSG = 5
ATT_MHTML_REF = 0x4

NAMES = {
    0x0002: "PR_ALTERNATE_RECIPIENT_ALLOWED",
    0x0017: "PR_IMPORTANCE",
    PR_MESSAGE_CLASS: "PR_MESSAGE_CLASS",
    0x0023: "PR_ORIGINATOR_DELIVERY_REPORT_REQUESTED",
    0x0026: "PR_PRIORITY",
    0x0029: "PR_READ_RECEIPT_REQUESTED",
    0x0036: "PR_SENSITIVITY",
    PR_SUBJECT: "PR_SUBJECT",
    PR_CLIENT_SUBMIT_TIME: "PR_CLIENT_SUBMIT_TIME",
    0x003B: "PR_SENT_REPRESENTING_SEARCH_KEY",
    0x003D: "PR_SUBJECT_PREFIX",
    0x003F: "PR_RECEIVED_BY_ENTRYID",
    0x0040: "PR_RECEIVED_BY_NAME",
    0x0041: "PR_SENT_REPRESENTING_ENTRYID",
    PR_SENT_REPRESENTING_NAME: "PR_SENT_REPRESENTING_NAME",
    0x0043: "PR_RCVD_REPRESENTING_ENTRYID",
    0x0044: "PR_RCVD_REPRESENTING_NAME",
    0x004F: "PR_REPLY_RECIPIENT_ENTRIES",
    0x0050: "PR_REPLY_RECIPIENT_NAMES",
    0x0051: "PR_RECEIVED_BY_SEARCH_KEY",
    0x0052: "PR_RCVD_REPRESENTING_SEARCH_KEY",
    PR_SENT_REPRESENTING_ADDRTYPE: "PR_SENT_REPRESENTING_ADDRTYPE",
    PR_SENT_REPRESENTING_EMAIL_ADDRESS: "PR_SENT_REPRESENTING_EMAIL_ADDRESS",
    PR_CONVERSATION_TOPIC: "PR_CONVERSATION_TOPIC",
    PR_CONVERSATION_INDEX: "PR_CONVERSATION_INDEX",
    0x0075: "PR_RECEIVED_BY_ADDRTYPE",
    0x0076: "PR_RECEIVED_BY_EMAIL_ADDRESS",
    0x0077: "PR_RCVD_REPRESENTING_ADDRTYPE",
    0x0078: "PR_RCVD_REPRESENTING_EMAIL_ADDRESS",
    PR_TRANSPORT_MESSAGE_HEADERS: "PR_TRANSPORT_MESSAGE_HEADERS",
    0x0C17: "PR_REPLY_REQUESTED",
    0x0C19: "PR_SENDER_ENTRYID",
    PR_SENDER_NAME: "PR_SENDER_NAME",
    0x0C1D: "PR_SENDER_SEARCH_KEY",
    PR_SENDER_ADDRTYPE: "PR_SENDER_ADDRTYPE",
    PR_SENDER_EMAIL_ADDRESS: "PR_SENDER_EMAIL_ADDRESS",
    PR_RECIPIENT_TYPE: "PR_RECIPIENT_TYPE",
    0x0E01: "PR_DELETE_AFTER_SUBMIT",
    0x0E02: "PR_DISPLAY_BCC",
    0x0E03: "PR_DISPLAY_CC",
    0x0E04: "PR_DISPLAY_TO",
    PR_MESSAGE_DELIVERY_TIME: "PR_MESSAGE_DELIVERY_TIME",
    PR_MESSAGE_FLAGS: "PR_MESSAGE_FLAGS",
    0x0E08: "PR_MESSAGE_SIZE",
    0x0E1D: "PR_NORMALIZED_SUBJECT",
    0x0E20: "PR_ATTACH_SIZE",
    0x0E21: "PR_ATTACH_NUM",
    PR_BODY: "PR_BODY",
    PR_RTF_COMPRESSED: "PR_RTF_COMPRESSED",
    PR_HTML: "PR_HTML",
    PR_INTERNET_MESSAGE_ID: "PR_INTERNET_MESSAGE_ID",
    PR_INTERNET_REFERENCES: "PR_INTERNET_REFERENCES",
    PR_IN_REPLY_TO_ID: "PR_IN_REPLY_TO_ID",
    0x1046: "PR_INTERNET_RETURN_PATH",
    0x1080: "PR_ICON_INDEX",
    PR_DISPLAY_NAME: "PR_DISPLAY_NAME",
    PR_ADDRTYPE: "PR_ADDRTYPE",
    PR_EMAIL_ADDRESS: "PR_EMAIL_ADDRESS",
    PR_CREATION_TIME: "PR_CREATION_TIME",
    PR_LAST_MODIFICATION_TIME: "PR_LAST_MODIFICATION_TIME",
    0x300B: "PR_SEARCH_KEY",
    0x3016: "PR_CONVERSATION_INDEX_TRACKING",
    PR_ATTACH_DATA: "PR_ATTACH_DATA",
    PR_ATTACH_FILENAME: "PR_ATTACH_FILENAME",
    PR_ATTACH_METHOD: "PR_ATTACH_METHOD",
    PR_ATTACH_LONG_FILENAME: "PR_ATTACH_LONG_FILENAME",
    0x370B: "PR_RENDERING_POSITION",
    0x370D: "PR_ATTACH_LONG_PATHNAME",
    PR_ATTACH_MIME_TAG: "PR_ATTACH_MIME_TAG",
    PR_ATTACH_CONTENT_ID: "PR_ATTACH_CONTENT_ID",
    PR_ATTACH_FLAGS: "PR_ATTACH_FLAGS",
    0x3900: "PR_DISPLAY_TYPE",
    PR_SMTP_ADDRESS: "PR_SMTP_ADDRESS",
    PR_INTERNET_CPID: "PR_INTERNET_CPID",
    0x3FF1: "PR_MESSAGE_LOCALE_ID",
    PR_LAST_MODIFIER_NAME: "PR_LAST_MODIFIER_NAME",
    PR_MESSAGE_CODEPAGE: "PR_MESSAGE_CODEPAGE",
    0x4022: "PR_CREATOR_ADDRTYPE",
    0x4023: "PR_CREATOR_EMAIL_ADDRESS",
    0x4024: "PR_LAST_MODIFIER_ADDRTYPE",
    0x4025: "PR_LAST_MODIFIER_EMAIL_ADDRESS",
    PR_SENDER_SMTP_ADDRESS: "PR_SENDER_SMTP_ADDRESS",
    PR_SENT_REPRESENTING_SMTP_ADDRESS: "PR_SENT_REPRESENTING_SMTP_ADDRESS",
    PR_ATTACHMENT_HIDDEN: "PR_ATTACHMENT_HIDDEN",
}

NOT_IN_JSON = {PR_BODY, PR_HTML, PR_RTF_COMPRESSED, PR_ATTACH_DATA, PR_TRANSPORT_MESSAGE_HEADERS}
MAX_JSON_BINARY = 64 * 1024

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_RECIPIENT_TYPES = {1: "to", 2: "cc", 3: "bcc"}
_HEADER_ONLY_DEFECTS = {
    "StartBoundaryNotFoundDefect",
    "CloseBoundaryNotFoundDefect",
    "MultipartInvariantViolationDefect",
}
_CODEPAGES = {
    1200: "utf-16-le",
    1201: "utf-16-be",
    20127: "ascii",
    20866: "koi8_r",
    21866: "koi8_u",
    50220: "iso2022_jp",
    50221: "iso2022_jp",
    50222: "iso2022_jp",
    51932: "euc_jp",
    51949: "euc_kr",
    52936: "hz",
    54936: "gb18030",
    65000: "utf-7",
    65001: "utf-8",
}


@dataclass(frozen=True)
class NamedProp:
    guid: str
    lid: int | None
    name: str | None

    def key(self) -> str:
        return f"{{{self.guid}}}:{self.name}" if self.name is not None else f"{{{self.guid}}}:0x{self.lid:04x}"


@dataclass
class Prop:
    id: int
    type: int
    data: bytes | None
    named: NamedProp | None = None


Props = dict[int, Prop]


@dataclass
class MapiAttachment:
    props: Props
    embedded: MapiItem | None = None


@dataclass
class MapiItem:
    props: Props
    recipients: list[Props] = field(default_factory=list)
    attachments: list[MapiAttachment] = field(default_factory=list)
    codepage: str = "cp1252"
    defects: list[str] = field(default_factory=list)


def python_codec(codepage: int | None, default: str = "cp1252") -> str:
    if not codepage:
        return default
    if codepage in _CODEPAGES:
        return _CODEPAGES[codepage]
    if 28591 <= codepage <= 28606:
        return f"iso8859_{codepage - 28590}"
    try:
        return codecs.lookup(f"cp{codepage}").name
    except LookupError:
        return default


def parse_name_map(guids: bytes, entries: bytes, strings: bytes) -> dict[int, NamedProp]:
    guid_list = [str(uuid.UUID(bytes_le=guids[i : i + 16])) for i in range(0, len(guids) - 15, 16)]
    out: dict[int, NamedProp] = {}
    for off in range(0, len(entries) - 7, 8):
        ident, kind_guid, index = struct.unpack_from("<IHH", entries, off)
        g = kind_guid >> 1
        if g == 1:
            guid = PS_MAPI
        elif g == 2:
            guid = PS_PUBLIC_STRINGS
        elif 0 <= g - 3 < len(guid_list):
            guid = guid_list[g - 3]
        else:
            continue
        if kind_guid & 1:
            if ident + 4 > len(strings):
                continue
            (n,) = struct.unpack_from("<I", strings, ident)
            name = strings[ident + 4 : ident + 4 + n].decode("utf-16-le", "replace")
            out[0x8000 + index] = NamedProp(guid, None, name)
        else:
            out[0x8000 + index] = NamedProp(guid, ident, None)
    return out


def filetime(data: bytes) -> datetime | None:
    if len(data) < 8:
        return None
    ticks = int.from_bytes(data[:8], "little")
    if ticks == 0:
        return None
    try:
        return _FILETIME_EPOCH + timedelta(microseconds=ticks // 10)
    except OverflowError:
        return None


def _scalar(ptype: int, data: bytes, codepage: str):
    if ptype == PT_UNICODE:
        return data[: len(data) // 2 * 2].decode("utf-16-le", "replace").rstrip("\x00")
    if ptype == PT_STRING8:
        return data.decode(codepage, "replace").rstrip("\x00")
    if ptype == PT_SYSTIME:
        return filetime(data)
    if ptype == PT_BOOLEAN:
        return bool(data[:1]) and data[0] != 0
    size = FIXED_SIZE.get(ptype)
    if size is None or len(data) < size:
        return data
    if ptype == PT_SHORT:
        return struct.unpack_from("<h", data)[0]
    if ptype == PT_LONG:
        return struct.unpack_from("<i", data)[0]
    if ptype == PT_ERROR:
        return struct.unpack_from("<I", data)[0]
    if ptype == PT_FLOAT:
        return struct.unpack_from("<f", data)[0]
    if ptype in (PT_DOUBLE, PT_APPTIME):
        return struct.unpack_from("<d", data)[0]
    if ptype in (PT_LONGLONG, PT_CURRENCY):
        return struct.unpack_from("<q", data)[0]
    if ptype == PT_CLSID:
        return str(uuid.UUID(bytes_le=data[:16]))
    return data


def _multi(ptype: int, data: bytes, codepage: str) -> list | None:
    if ptype in VARIABLE:
        if len(data) < 4:
            return []
        (count,) = struct.unpack_from("<I", data)
        if 4 + 4 * count > len(data):
            return None
        offsets = list(struct.unpack_from(f"<{count}I", data, 4)) + [len(data)]
        if any(not (4 + 4 * count <= a <= b <= len(data)) for a, b in zip(offsets, offsets[1:])):
            return None
        return [_scalar(ptype, data[a:b], codepage) for a, b in zip(offsets, offsets[1:])]
    size = FIXED_SIZE.get(ptype)
    if size is None:
        return None
    return [_scalar(ptype, data[i : i + size], codepage) for i in range(0, len(data) - size + 1, size)]


def pack_multi(values: list[bytes]) -> bytes:
    head = 4 + 4 * len(values)
    offsets, pos = [], head
    for v in values:
        offsets.append(pos)
        pos += len(v)
    return struct.pack(f"<I{len(values)}I", len(values), *offsets) + b"".join(values)


def decode(prop: Prop | None, codepage: str = "cp1252"):
    if prop is None or prop.data is None:
        return None
    if prop.type & MV_FLAG:
        return _multi(prop.type & ~MV_FLAG, prop.data, codepage)
    return _scalar(prop.type, prop.data, codepage)


def _jsonable(v):
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, bytes):
        if len(v) > MAX_JSON_BINARY:
            return {"size": len(v), "sha256": sha256_bytes(v)}
        return v.hex()
    if isinstance(v, str):
        return clean(v)
    if isinstance(v, float) and v != v:
        return None
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


def props_json(props: Props, codepage: str) -> dict:
    out = {}
    for p in sorted(props.values(), key=lambda p: (p.id, p.type)):
        if p.id in NOT_IN_JSON:
            continue
        tag = f"0x{p.id:04x}{p.type:04x}"
        entry: dict = {"value": _jsonable(decode(p, codepage))}
        if p.named is not None:
            entry["tag"] = tag
            out[f"{p.named.key()}:0x{p.type:04x}"] = entry
        else:
            if p.id in NAMES:
                entry["name"] = NAMES[p.id]
            out[tag] = entry
    return out


def _canonical_props(props: Props) -> bytes:
    keyed = []
    for p in props.values():
        if p.named is not None:
            key = b"N" + p.named.key().encode("utf-8") + struct.pack("<H", p.type)
        else:
            key = b"T" + struct.pack(">HH", p.id, p.type)
        keyed.append((key, p.data))
    out = bytearray()
    for key, data in sorted(keyed, key=lambda kv: kv[0]):
        out += struct.pack("<I", len(key)) + key
        out += b"\xff" * 8 if data is None else struct.pack("<Q", len(data)) + data
    return bytes(out)


def canonical_bytes(item: MapiItem) -> bytes:
    out = bytearray(b"EFMAPI1\n")
    out += b"P" + _canonical_props(item.props)
    for r in item.recipients:
        out += b"R" + _canonical_props(r)
    for a in item.attachments:
        out += b"A" + _canonical_props(a.props)
        if a.embedded is not None:
            inner = canonical_bytes(a.embedded)
            out += b"E" + struct.pack("<Q", len(inner)) + inner
    return bytes(out)


def item_codepage(props: Props, default: str) -> str:
    cp = decode(props.get(PR_MESSAGE_CODEPAGE))
    return python_codec(cp if isinstance(cp, int) else None, default)


def _text(props: Props, pid: int, codepage: str) -> str | None:
    v = decode(props.get(pid), codepage)
    if isinstance(v, bytes):
        v = v.decode(codepage, "replace")
    return clean(v) if isinstance(v, str) and v != "" else None


def _subject(props: Props, codepage: str) -> str | None:
    s = _text(props, PR_SUBJECT, codepage)
    if s and s[0] == "\x01" and len(s) >= 2:
        s = s[2:]
    return s or None


def _person(props: Props, name: int, smtp: int, address: int, codepage: str) -> list[dict]:
    display = _text(props, name, codepage)
    addr = _text(props, smtp, codepage) or _text(props, address, codepage)
    return [{"name": display, "address": addr}] if display or addr else []


def _recipient(props: Props, codepage: str) -> dict:
    rtype = decode(props.get(PR_RECIPIENT_TYPE))
    return {
        "type": _RECIPIENT_TYPES.get(rtype & 0x0F, rtype) if isinstance(rtype, int) else None,
        "name": _text(props, PR_DISPLAY_NAME, codepage),
        "address": _text(props, PR_EMAIL_ADDRESS, codepage),
        "addrtype": _text(props, PR_ADDRTYPE, codepage),
        "smtp": _text(props, PR_SMTP_ADDRESS, codepage),
    }


def _html(props: Props, codepage: str) -> str | None:
    p = props.get(PR_HTML)
    if p is None or p.data is None:
        return None
    if p.type == PT_UNICODE:
        return _text(props, PR_HTML, codepage)
    cpid = decode(props.get(PR_INTERNET_CPID))
    codec = python_codec(cpid if isinstance(cpid, int) else None, codepage)
    return clean(p.data.decode(codec, "replace").rstrip("\x00")) or None


def _attachment(index: int, att: MapiAttachment, codepage: str, children: list, defects: list) -> Attachment:
    props = att.props
    mime_path = str(index)
    method = decode(props.get(PR_ATTACH_METHOD))
    flags = decode(props.get(PR_ATTACH_FLAGS))
    hidden = decode(props.get(PR_ATTACHMENT_HIDDEN)) is True
    inline = hidden or (isinstance(flags, int) and bool(flags & ATT_MHTML_REF))

    if att.embedded is not None:
        data = canonical_bytes(att.embedded)
        content_type = "application/vnd.ms-outlook"
        children.append((mime_path, to_parsed(att.embedded)))
    else:
        raw = props.get(PR_ATTACH_DATA)
        data = raw.data if raw is not None and raw.data is not None else b""
        content_type = _text(props, PR_ATTACH_MIME_TAG, codepage) or "application/octet-stream"
        if method == ATTACH_EMBEDDED_MSG:
            defects.append(f"attachment {mime_path}: embedded message could not be read")

    return Attachment(
        mime_path=mime_path,
        filename=_text(props, PR_ATTACH_LONG_FILENAME, codepage)
        or _text(props, PR_ATTACH_FILENAME, codepage)
        or _text(props, PR_DISPLAY_NAME, codepage),
        content_type=content_type,
        disposition="inline" if inline else "attachment",
        content_id=_text(props, PR_ATTACH_CONTENT_ID, codepage),
        data=data,
        mapi_props=props_json(props, codepage),
    )


def to_parsed(item: MapiItem) -> ParsedMessage:
    p, cp = item.props, item.codepage
    defects: list[str] = list(item.defects)

    raw_headers = _text(p, PR_TRANSPORT_MESSAGE_HEADERS, cp)
    hp = None
    if raw_headers:
        hp = parse_message(raw_headers.strip("\r\n").encode("utf-8", "surrogateescape") + b"\r\n\r\n")
        defects.extend(d for d in hp.defects if d not in _HEADER_ONLY_DEFECTS)

    submit = decode(p.get(PR_CLIENT_SUBMIT_TIME))
    delivery = decode(p.get(PR_MESSAGE_DELIVERY_TIME))
    recipients = [_recipient(r, cp) for r in item.recipients]

    def mapi_addrs(kind: str) -> list[dict]:
        return [
            {"name": r["name"], "address": r["smtp"] or r["address"]}
            for r in recipients
            if r["type"] == kind and (r["name"] or r["smtp"] or r["address"])
        ]

    representing = _person(
        p, PR_SENT_REPRESENTING_NAME, PR_SENT_REPRESENTING_SMTP_ADDRESS, PR_SENT_REPRESENTING_EMAIL_ADDRESS, cp
    )
    sender = _person(p, PR_SENDER_NAME, PR_SENDER_SMTP_ADDRESS, PR_SENDER_EMAIL_ADDRESS, cp)

    if hp is not None and hp.date_utc is not None:
        date_raw, date_utc, offset = hp.date_raw, hp.date_utc, hp.date_offset_minutes
    else:
        date_raw, offset = None, None
        if submit is not None:
            date_utc = submit
            defects.append("no Date header; date_utc from PR_CLIENT_SUBMIT_TIME, offset unknown")
        elif delivery is not None:
            date_utc = delivery
            defects.append("no Date header; date_utc from PR_MESSAGE_DELIVERY_TIME, offset unknown")
        else:
            date_utc = None

    in_reply_to = (hp.in_reply_to if hp else None) or next(iter(msgids(_text(p, PR_IN_REPLY_TO_ID, cp))), None)

    attachments: list[Attachment] = []
    children: list = []
    for i, att in enumerate(item.attachments, 1):
        attachments.append(_attachment(i, att, cp, children, defects))

    body_text = _text(p, PR_BODY, cp)
    body_html = _html(p, cp)
    if body_text is None and body_html is None and PR_RTF_COMPRESSED in p:
        defects.append("body only stored as compressed RTF (PR_RTF_COMPRESSED)")

    conv_index = decode(p.get(PR_CONVERSATION_INDEX))

    return ParsedMessage(
        sha256=sha256_bytes(canonical_bytes(item)),
        headers=hp.headers if hp else [],
        rfc_message_id=(hp.rfc_message_id if hp else None) or _text(p, PR_INTERNET_MESSAGE_ID, cp),
        in_reply_to=in_reply_to,
        references=(hp.references if hp else []) or msgids(_text(p, PR_INTERNET_REFERENCES, cp)),
        subject=_subject(p, cp) or (hp.subject if hp else None),
        from_addr=(hp.from_addr if hp else []) or representing or sender,
        sender_addr=(hp.sender_addr if hp else []) or (sender if sender != representing and representing else []),
        to_addrs=(hp.to_addrs if hp else []) or mapi_addrs("to"),
        cc_addrs=(hp.cc_addrs if hp else []) or mapi_addrs("cc"),
        bcc_addrs=(hp.bcc_addrs if hp else []) or mapi_addrs("bcc"),
        reply_to=hp.reply_to if hp else [],
        date_raw=date_raw,
        date_utc=date_utc,
        date_offset_minutes=offset,
        body_text=body_text,
        body_html=body_html,
        defects=defects,
        attachments=attachments,
        children=children,
        mapi=MapiFields(
            message_class=_text(p, PR_MESSAGE_CLASS, cp),
            client_submit_time=submit,
            delivery_time=delivery,
            creation_time=decode(p.get(PR_CREATION_TIME)),
            last_modification_time=decode(p.get(PR_LAST_MODIFICATION_TIME)),
            last_modifier_name=_text(p, PR_LAST_MODIFIER_NAME, cp),
            sent_representing=representing,
            conversation_index=conv_index if isinstance(conv_index, bytes) else None,
            conversation_topic=_text(p, PR_CONVERSATION_TOPIC, cp),
            recipients=recipients,
            props=props_json(p, cp),
        ),
    )
