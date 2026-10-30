from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from emailforensics.hashing import sha256_bytes

_MSGID = re.compile(r"<[^<>\s]+>")
_FOLD = re.compile(r"\r?\n[ \t]+")


def clean(s: str | None) -> str | None:
    if s is None:
        return None
    try:
        b = s.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        b = s.encode("utf-8", "replace")
    return b.decode("utf-8", "replace").replace("\x00", "�")


@dataclass
class Attachment:
    mime_path: str
    filename: str | None
    content_type: str
    disposition: str | None
    content_id: str | None
    data: bytes = field(repr=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        self.sha256 = sha256_bytes(self.data)

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class ParsedMessage:
    sha256: str
    headers: list[tuple[str, str]]
    rfc_message_id: str | None
    in_reply_to: str | None
    references: list[str]
    subject: str | None
    from_addr: list[dict]
    sender_addr: list[dict]
    to_addrs: list[dict]
    cc_addrs: list[dict]
    bcc_addrs: list[dict]
    reply_to: list[dict]
    date_raw: str | None
    date_utc: datetime | None
    date_offset_minutes: int | None
    body_text: str | None
    body_html: str | None
    defects: list[str]
    attachments: list[Attachment]
    children: list[tuple[str, ParsedMessage]]


def _unfold(v: str | None) -> str | None:
    return _FOLD.sub(" ", v).strip() if v is not None else None


def _decode(v: str | None) -> str | None:
    if v is None:
        return None
    try:
        return str(make_header(decode_header(v)))
    except Exception:
        return v


def _all_raw(headers: list[tuple[str, str]], name: str) -> list[str]:
    lname = name.lower()
    return [_unfold(v) for n, v in headers if n.lower() == lname]


def _first_raw(headers: list[tuple[str, str]], name: str) -> str | None:
    values = _all_raw(headers, name)
    return values[0] if values else None


def _addresses(headers: list[tuple[str, str]], name: str) -> list[dict]:
    return [
        {"name": clean(_decode(n)) or None, "address": clean(a) or None}
        for n, a in getaddresses(_all_raw(headers, name))
        if n or a
    ]


def _msgids(v: str | None) -> list[str]:
    return _MSGID.findall(v) if v else []


def _parse_date(raw: str | None) -> tuple[datetime | None, int | None, list[str]]:
    if not raw:
        return None, None, []
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        return None, None, ["unparseable Date header"]
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc), None, ["Date offset -0000 (zone unknown)"]
    return dt.astimezone(timezone.utc), int(dt.utcoffset().total_seconds() // 60), []


def _content(part: Message) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        try:
            return payload.decode(part.get_content_charset() or "utf-8", "replace")
        except LookupError:
            return payload.decode("utf-8", "replace")


def _body(msg: Message, kind: str) -> str | None:
    try:
        part = msg.get_body(preferencelist=(kind,))
    except Exception:
        return None
    return clean(_content(part)) if part is not None else None


def _filename(part: Message) -> str | None:
    try:
        return clean(part.get_filename())
    except Exception:
        return None


def _is_attachment(part: Message) -> bool:
    if part.get_content_disposition() == "attachment" or _filename(part):
        return True
    return part.get_content_maintype() not in ("text", "multipart")


def _attachment(part: Message, path: str, data: bytes) -> Attachment:
    return Attachment(
        mime_path=path,
        filename=_filename(part),
        content_type=part.get_content_type(),
        disposition=part.get_content_disposition(),
        content_id=clean(_first_raw(list(part.raw_items()), "Content-ID")),
        data=data,
    )


def _serialise(inner: Message) -> bytes:
    try:
        return inner.as_bytes(policy=policy.compat32)
    except Exception:
        return inner.as_string(policy=policy.compat32).encode("utf-8", "surrogateescape")


def _walk(part: Message, path: str, atts: list, children: list, defects: list) -> None:
    defects.extend(type(d).__name__ for d in part.defects)
    if part.get_content_type() == "message/rfc822":
        payload = part.get_payload()
        if isinstance(payload, list) and payload:
            data = _serialise(payload[0])
            atts.append(_attachment(part, path or "1", data))
            children.append((path or "1", parse_message(data)))
        return
    if part.is_multipart():
        for i, sub in enumerate(part.get_payload(), 1):
            _walk(sub, f"{path}.{i}" if path else str(i), atts, children, defects)
        return
    if _is_attachment(part):
        atts.append(_attachment(part, path or "1", part.get_payload(decode=True) or b""))


def parse_message(raw: bytes) -> ParsedMessage:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = [(clean(n), clean(v)) for n, v in msg.raw_items()]

    date_raw = _first_raw(headers, "Date")
    date_utc, offset, defects = _parse_date(date_raw)

    attachments: list[Attachment] = []
    children: list[tuple[str, ParsedMessage]] = []
    _walk(msg, "", attachments, children, defects)

    msgid = _msgids(_first_raw(headers, "Message-ID"))
    in_reply_to = _msgids(_first_raw(headers, "In-Reply-To"))

    return ParsedMessage(
        sha256=sha256_bytes(raw),
        headers=headers,
        rfc_message_id=msgid[0] if msgid else clean(_first_raw(headers, "Message-ID")),
        in_reply_to=in_reply_to[0] if in_reply_to else None,
        references=_msgids(_first_raw(headers, "References")),
        subject=clean(_decode(_first_raw(headers, "Subject"))),
        from_addr=_addresses(headers, "From"),
        sender_addr=_addresses(headers, "Sender"),
        to_addrs=_addresses(headers, "To"),
        cc_addrs=_addresses(headers, "Cc"),
        bcc_addrs=_addresses(headers, "Bcc"),
        reply_to=_addresses(headers, "Reply-To"),
        date_raw=clean(date_raw),
        date_utc=date_utc,
        date_offset_minutes=offset,
        body_text=_body(msg, "plain"),
        body_html=_body(msg, "html"),
        defects=defects,
        attachments=attachments,
        children=children,
    )
