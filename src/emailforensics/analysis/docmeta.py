from __future__ import annotations

import io
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET

from emailforensics.analysis.metadata import _ips, ip_scope

MAX_DOC_BYTES = 200 << 20
MAX_PDF_STREAMS = 4000
MAX_STREAM_OUT = 8 << 20

NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
}
W = "{%s}" % NS["w"]
W16DU_DATE_UTC = "{http://schemas.microsoft.com/office/word/2023/wordml/word16du}dateUtc"
W16CEX = "http://schemas.microsoft.com/office/word/2018/wordml/cex"
W15 = "http://schemas.microsoft.com/office/word/2012/wordml"


@dataclass
class DocMeta:
    kind: str
    title: str | None = None
    author: str | None = None
    last_modified_by: str | None = None
    company: str | None = None
    application: str | None = None
    template: str | None = None
    created: datetime | None = None
    created_offset: int | None = None
    modified: datetime | None = None
    modified_offset: int | None = None
    editors: list[dict] = field(default_factory=list)
    esign: dict | None = None
    ips: list[dict] = field(default_factory=list)
    text_sample: str = ""
    detail: dict = field(default_factory=dict)


def _iso(s: str | None) -> tuple[datetime | None, int | None]:
    if not s:
        return None, None
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None, None
    if d.tzinfo is None:
        return d.replace(tzinfo=timezone.utc), None
    off = int(d.utcoffset().total_seconds() // 60)
    return d.astimezone(timezone.utc), off


def _xml(z: zipfile.ZipFile, name: str) -> ET.Element | None:
    try:
        with z.open(name) as f:
            return ET.fromstring(f.read(MAX_STREAM_OUT))
    except (KeyError, ET.ParseError, zipfile.BadZipFile, OSError):
        return None


def _text(root: ET.Element | None, path: str) -> str | None:
    if root is None:
        return None
    el = root.find(path, NS)
    return el.text.strip() if el is not None and el.text and el.text.strip() else None


def _local_vs_utc(local: str | None, utc: str | None) -> int | None:
    if not local or not utc:
        return None
    try:
        a = datetime.fromisoformat(local.replace("Z", "")).replace(tzinfo=None)
        b = datetime.fromisoformat(utc.replace("Z", "")).replace(tzinfo=None)
    except ValueError:
        return None
    diff = (a - b).total_seconds() / 60
    off = int(round(diff / 15) * 15)
    return off if abs(diff - off) <= 2 and abs(off) <= 14 * 60 else None


def ooxml(data: bytes) -> DocMeta | None:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None
    names = set(z.namelist())
    if "[Content_Types].xml" not in names:
        return None
    kind = "docx" if "word/document.xml" in names else "xlsx" if "xl/workbook.xml" in names else (
        "pptx" if "ppt/presentation.xml" in names else "ooxml"
    )
    core = _xml(z, "docProps/core.xml")
    app = _xml(z, "docProps/app.xml")
    created, c_off = _iso(_text(core, "dcterms:created"))
    modified, m_off = _iso(_text(core, "dcterms:modified"))
    meta = DocMeta(
        kind=kind,
        title=_text(core, "dc:title"),
        author=_text(core, "dc:creator"),
        last_modified_by=_text(core, "cp:lastModifiedBy"),
        company=_text(app, "ep:Company"),
        application=_text(app, "ep:Application"),
        template=_text(app, "ep:Template"),
        created=created,
        created_offset=c_off,
        modified=modified,
        modified_offset=m_off,
    )
    meta.detail = {
        k: v
        for k, v in {
            "revision": _text(core, "cp:revision"),
            "last_printed": _text(core, "cp:lastPrinted"),
            "manager": _text(app, "ep:Manager"),
            "total_edit_minutes": _text(app, "ep:TotalTime"),
            "app_version": _text(app, "ep:AppVersion"),
        }.items()
        if v
    }
    if kind == "docx":
        editors: dict[tuple[str, str], dict] = {}
        for part in ("word/document.xml", "word/footnotes.xml", "word/endnotes.xml"):
            root = _xml(z, part)
            if root is None:
                continue
            for el in root.iter():
                tag = el.tag
                if tag in (W + "ins", W + "del", W + "moveFrom", W + "moveTo", W + "rPrChange", W + "pPrChange"):
                    author = el.get(W + "author")
                    if not author:
                        continue
                    local = el.get(W + "date")
                    utc = el.get(W16DU_DATE_UTC)
                    e = editors.setdefault(("revision", author), {"type": "revision", "author": author, "count": 0, "dates": [], "offsets": []})
                    e["count"] += 1
                    if local:
                        e["dates"].append(local)
                    off = _local_vs_utc(local, utc)
                    if off is not None:
                        e["offsets"].append(off)
        comments = _xml(z, "word/comments.xml")
        cex = _xml(z, "word/commentsExtensible.xml")
        cex_utc = {}
        if cex is not None:
            for el in cex.iter():
                if el.get("{%s}dateUtc" % W16CEX):
                    cex_utc[el.get("{%s}durableId" % W16CEX)] = el.get("{%s}dateUtc" % W16CEX)
        if comments is not None:
            for el in comments.iter(W + "comment"):
                author = el.get(W + "author")
                if not author:
                    continue
                e = editors.setdefault(("comment", author), {"type": "comment", "author": author, "count": 0, "dates": [], "offsets": []})
                e["count"] += 1
                if el.get(W + "date"):
                    e["dates"].append(el.get(W + "date"))
        for e in editors.values():
            e["first"] = min(e["dates"]) if e["dates"] else None
            e["last"] = max(e["dates"]) if e["dates"] else None
            e["offsets"] = sorted(set(e["offsets"]))
            del e["dates"]
        meta.editors = sorted(editors.values(), key=lambda e: (e["type"], e["author"]))
        people = _xml(z, "word/people.xml")
        if people is not None:
            meta.detail["people"] = sorted({el.get("{%s}author" % W15) for el in people.iter() if el.get("{%s}author" % W15)})
        doc = _xml(z, "word/document.xml")
        if doc is not None:
            meta.text_sample = " ".join(t.text for t in doc.iter(W + "t") if t.text)[:20000]
    return meta


def ole(data: bytes) -> DocMeta | None:
    try:
        import olefile
    except ImportError:
        return None
    try:
        f = olefile.OleFileIO(io.BytesIO(data))
    except Exception:
        return None
    try:
        if f.exists("__substg1.0_0037001F") or f.exists("__properties_version1.0"):
            return None
        m = f.get_metadata()
    except Exception:
        return None
    finally:
        f.close()

    def s(v):
        if isinstance(v, bytes):
            return v.decode("cp1252", "replace").strip("\x00 ").strip() or None
        return v

    def t(v):
        return v.replace(tzinfo=timezone.utc) if isinstance(v, datetime) else None

    return DocMeta(
        kind="ole",
        title=s(m.title),
        author=s(m.author),
        last_modified_by=s(m.last_saved_by),
        company=s(getattr(m, "company", None)),
        application=s(m.creating_application),
        template=s(m.template),
        created=t(m.create_time),
        modified=t(m.last_saved_time),
        detail={k: v for k, v in {"revision": s(m.revision_number), "manager": s(getattr(m, "manager", None))}.items() if v},
    )


_PDF_DATE = re.compile(rb"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([Zz+\-])?(\d{2})?'?(\d{2})?'?")


def pdf_date(raw: bytes) -> tuple[datetime | None, int | None]:
    m = _PDF_DATE.search(raw)
    if not m:
        return None, None
    parts = [int(x) if x else d for x, d in zip(m.groups()[:6], (0, 1, 1, 0, 0, 0))]
    try:
        local = datetime(*parts)
    except ValueError:
        return None, None
    sign = m.group(7)
    if sign in (b"+", b"-"):
        off = int(m.group(8) or 0) * 60 + int(m.group(9) or 0)
        off = off if sign == b"+" else -off
        return (local - timedelta(minutes=off)).replace(tzinfo=timezone.utc), off
    if sign in (b"Z", b"z"):
        return local.replace(tzinfo=timezone.utc), 0
    return local.replace(tzinfo=timezone.utc), None


def _pdf_string(chunk: bytes, key: bytes) -> bytes | None:
    m = re.search(rb"/" + key + rb"\s*\(((?:\\.|[^\\)])*)\)", chunk, re.S)
    if m:
        return m.group(1)
    m = re.search(rb"/" + key + rb"\s*<([0-9A-Fa-f\s]+)>", chunk)
    if m:
        try:
            return bytes.fromhex(re.sub(rb"\s", b"", m.group(1)).decode())
        except ValueError:
            return None
    return None


def _decode_pdf_text(b: bytes | None) -> str | None:
    if b is None:
        return None
    if b.startswith(b"\xfe\xff"):
        return b[2:].decode("utf-16-be", "replace").strip() or None
    b = re.sub(rb"\\([()\\])", rb"\1", b)
    return b.decode("latin-1", "replace").strip() or None


def _xmp(blob: bytes, tag: str) -> str | None:
    m = re.search(rb"<" + tag.encode() + rb">\s*(?:<rdf:(?:Seq|Alt|Bag)>\s*<rdf:li[^>]*>)?([^<]+)", blob)
    if m:
        return m.group(1).decode("utf-8", "replace").strip()
    m = re.search(tag.encode() + rb'="([^"]+)"', blob)
    return m.group(1).decode("utf-8", "replace").strip() if m else None


def _pdf_streams(data: bytes) -> list[bytes]:
    out = []
    for i, m in enumerate(re.finditer(rb"stream\r?\n", data)):
        if i >= MAX_PDF_STREAMS:
            break
        end = data.find(b"endstream", m.end())
        if end < 0:
            break
        raw = data[m.end() : end]
        try:
            d = zlib.decompressobj()
            out.append(d.decompress(raw, MAX_STREAM_OUT))
        except zlib.error:
            continue
    return out


def _pdf_text(streams: list[bytes]) -> str:
    parts = []
    for s in streams:
        for m in re.finditer(rb"\(((?:\\.|[^\\)]){1,400})\)\s*'?T[jJ']?|\[((?:[^\]]){1,2000})\]\s*TJ", s):
            if m.group(1) is not None:
                parts.append(_decode_pdf_text(m.group(1)) or "")
            else:
                parts.append("".join(_decode_pdf_text(x) or "" for x in re.findall(rb"\(((?:\\.|[^\\)])*)\)", m.group(2))))
        if sum(len(p) for p in parts) > 400_000:
            break
    return re.sub(r"[ \t]+", " ", " ".join(parts))


_ESIGN = re.compile(
    r"(certificate of completion|envelope id|docusign|adobe (?:acrobat )?sign|echosign|signnow|"
    r"pandadoc|hellosign|dropbox sign|signing log|audit trail|transaction id)",
    re.I,
)


def pdf(data: bytes) -> DocMeta:
    head = data[: 1 << 20] + data[-(1 << 20) :]
    streams = _pdf_streams(data)
    joined = head + b"".join(s for s in streams if b"/CreationDate" in s or b"/Producer" in s or b"xmpmeta" in s)
    info_at = joined.find(b"/CreationDate")
    info = joined[max(0, info_at - 2000) : info_at + 2000] if info_at >= 0 else joined
    created, c_off = pdf_date(_pdf_string(info, b"CreationDate") or b"")
    modified, m_off = pdf_date(_pdf_string(info, b"ModDate") or b"")
    xmp_create, x_c_off = _iso(_xmp(joined, "xmp:CreateDate"))
    xmp_modify, x_m_off = _iso(_xmp(joined, "xmp:ModifyDate"))
    meta = DocMeta(
        kind="pdf",
        title=_decode_pdf_text(_pdf_string(info, b"Title")) or _xmp(joined, "dc:title"),
        author=_decode_pdf_text(_pdf_string(info, b"Author")) or _xmp(joined, "dc:creator"),
        application=_decode_pdf_text(_pdf_string(info, b"Creator")) or _xmp(joined, "xmp:CreatorTool"),
        created=created or xmp_create,
        created_offset=c_off if c_off is not None else x_c_off,
        modified=modified or xmp_modify,
        modified_offset=m_off if m_off is not None else x_m_off,
    )
    producer = _decode_pdf_text(_pdf_string(info, b"Producer")) or _xmp(joined, "pdf:Producer")
    meta.detail = {k: v for k, v in {"producer": producer, "xmp_create_offset": x_c_off, "xmp_modify_offset": x_m_off}.items() if v is not None}
    text = _pdf_text(streams)
    meta.text_sample = text[:20000]
    hits = sorted({m.group(1).lower() for m in _ESIGN.finditer(text + " " + (producer or "") + " " + (meta.application or ""))})
    if hits:
        ips = []
        for ip in _ips(text):
            if ip_scope(ip) != "public":
                continue
            i = text.find(ip)
            ips.append({"ip": ip, "context": text[max(0, i - 160) : i + 60].strip()})
        meta.esign = {"markers": hits, "ips_found": len(ips), "text_extracted": len(text) > 200}
        meta.ips = ips
    return meta


def scrub(v):
    if isinstance(v, str):
        return v.replace("\x00", "")
    if isinstance(v, dict):
        return {scrub(k): scrub(x) for k, x in v.items()}
    if isinstance(v, list):
        return [scrub(x) for x in v]
    return v


def analyse(data: bytes, filename: str | None, content_type: str | None) -> DocMeta | None:
    if not data or len(data) > MAX_DOC_BYTES:
        return None
    meta = _detect(data)
    if meta is not None:
        for name, value in vars(meta).items():
            setattr(meta, name, scrub(value))
    return meta


def _detect(data: bytes) -> DocMeta | None:
    if data[:4] == b"PK\x03\x04":
        return ooxml(data)
    if data[:5] == b"%PDF-" or (data[:1024].find(b"%PDF-") >= 0):
        return pdf(data)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return ole(data)
    return None
